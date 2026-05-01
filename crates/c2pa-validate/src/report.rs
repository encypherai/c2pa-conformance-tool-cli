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

use std::process::ExitCode;

use c2pa::validation_results::ValidationState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrJsonReport {
    pub schema: &'static str,
    pub schema_version: &'static str,
    pub tool: ToolMetadata,
    pub generated_at: String,
    pub summary: Summary,
    pub results: Vec<ReportItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub c2pa_sdk: SdkMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    pub total: usize,
    pub trusted: usize,
    pub valid: usize,
    pub invalid: usize,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportItem {
    Asset(AssetReport),
    CrJsonValidation(CrJsonValidationReport),
}

impl ReportItem {
    /// Resolved path of the input file for this result.
    pub fn input_path(&self) -> &str {
        match self {
            ReportItem::Asset(r) => &r.input.resolved_path,
            ReportItem::CrJsonValidation(r) => &r.input.resolved_path,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetReport {
    pub input: InputDescriptor,
    pub validation_state: ValidationState,
    pub trust: TrustAssessment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_evaluation: Option<serde_json::Value>,
    pub active_manifest_label: Option<String>,
    pub manifest_count: usize,
    pub ingredient_count: usize,
    pub assertion_labels: Vec<String>,
    pub statuses: Vec<StatusRecord>,
    pub manifests: Vec<ManifestRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrJsonValidationReport {
    pub input: InputDescriptor,
    pub valid: bool,
    pub messages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rubric_results: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub original: String,
    pub resolved_path: String,
    pub input_type: InputType,
    pub detected_format: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    Asset,
    SidecarManifest,
    CrJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAssessment {
    pub mode: String,
    pub classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRecord {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecord {
    pub label: Option<String>,
    pub title: Option<String>,
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_version: Option<String>,
    pub claim_generator: Option<String>,
    pub signature: Option<SignatureRecord>,
    pub ingredients: Vec<IngredientRecord>,
    pub assertions: Vec<AssertionRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<StatusRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    pub alg: Option<String>,
    pub issuer: Option<String>,
    pub common_name: Option<String>,
    pub serial_number: Option<String>,
    pub time: Option<String>,
    pub revoked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngredientRecord {
    pub title: Option<String>,
    pub format: Option<String>,
    pub relationship: Option<String>,
    pub active_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionRecord {
    pub label: String,
    pub instance: usize,
    pub kind: String,
}

impl CrJsonReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.summary.errors > 0 || self.summary.invalid > 0 {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }

    pub fn render_markdown(&self, profile_only: bool) -> String {
        let mut output = String::new();
        if profile_only {
            output.push_str("# 📝 C2PA Conformance Report\n\n");
        } else {
            output.push_str("# C2PA Conformance Report\n\n");
        }

        let result = match self.results.first() {
            Some(r) => r,
            None => {
                output.push_str("## Report Generation Info\n\n");
                output.push_str(&format!(
                    "**Tool:** {} {}  \n**Generated:** {}\n",
                    self.tool.name, self.tool.version, self.generated_at
                ));
                return output;
            }
        };

        match result {
            ReportItem::Asset(report) => {
                if profile_only {
                    output.push_str(&format!("**📁 Asset:** {}\n\n", report.input.resolved_path));
                    output.push_str(&format!(
                        "**📄 Format:** {}\n\n",
                        report.input.detected_format
                    ));
                } else {
                    output.push_str(&format!("**Asset:** {}\n\n", report.input.resolved_path));
                    output.push_str(&format!("**Format:** {}\n\n", report.input.detected_format));
                }

                if profile_only {
                    // Profile report: compliance and profile details at top; no Validation & Trust or Manifests.
                    if let Some(profile_path) = &report.profile_path {
                        output.push_str("## 📝 Profile\n\n");
                        let comp = render_profile_compliance(report.profile_evaluation.as_ref());
                        output.push_str(&format!(
                            "- **Profile:** `{}`\n- **Compliance:** {}\n\n",
                            profile_path,
                            compliance_emoji_md(comp)
                        ));
                        if let Some(ref eval) = report.profile_evaluation {
                            output.push_str(&render_profile_details_md(eval));
                        }
                    }
                } else {
                    output.push_str("## Validation & Trust\n\n");
                    output.push_str(&format!(
                        "- **Trust Status:** `{}`\n",
                        render_state(report.validation_state)
                    ));
                    if !report.trust.notes.is_empty() {
                        for note in &report.trust.notes {
                            output.push_str(&format!("- **Note:** {}\n", note));
                        }
                    }
                    let (claim_sig, signing_cert, timestamp) =
                        partition_validation_statuses(&report.statuses);
                    if !claim_sig.is_empty() {
                        output.push_str("- **Claim signature:** ");
                        output.push_str(&format_status_list(claim_sig));
                        output.push_str("\n");
                    }
                    if !signing_cert.is_empty() {
                        output.push_str("- **Signing certificate:** ");
                        output.push_str(&format_status_list(signing_cert));
                        output.push_str("\n");
                    }
                    if !timestamp.is_empty() {
                        output.push_str("- **Timestamp:** ");
                        output.push_str(&format_status_list(timestamp));
                        output.push_str("\n");
                    }
                    output.push_str("\n");

                    if let Some(profile_path) = &report.profile_path {
                        output.push_str("## Profile\n\n");
                        output.push_str(&format!(
                            "- **Profile:** `{}`\n- **Compliance:** `{}`\n\n",
                            profile_path,
                            render_profile_compliance(report.profile_evaluation.as_ref())
                        ));
                    }

                    output.push_str("## Manifests\n\n");
                    for (i, manifest) in report.manifests.iter().enumerate() {
                        let heading = manifest
                            .title
                            .as_deref()
                            .or(manifest.label.as_deref())
                            .unwrap_or("(unnamed)");
                        output.push_str(&format!("### Manifest {}: {}\n\n", i + 1, heading));

                        output.push_str("#### Claim\n\n");
                        if let Some(ref v) = manifest.claim_version {
                            output.push_str(&format!("- **Claim version:** {}\n", v));
                        }
                        if let Some(ref gen) = manifest.claim_generator {
                            output.push_str(&format!("- **Claim generator:** {}\n", gen));
                        }
                        if manifest.claim_version.is_none() && manifest.claim_generator.is_none() {
                            output.push_str("- *(none)*\n");
                        }
                        output.push_str("\n");

                        output.push_str("#### Signature Info\n\n");
                        if let Some(ref sig) = manifest.signature {
                            if let Some(ref cn) = sig.common_name {
                                output.push_str(&format!("- **Signing (CN):** {}\n", cn));
                            }
                            if let Some(ref issuer) = sig.issuer {
                                output.push_str(&format!("- **Issuer:** {}\n", issuer));
                            }
                            if let Some(ref t) = sig.time {
                                output.push_str(&format!("- **Time:** {}\n", t));
                            }
                        }
                        if manifest.signature.is_none() {
                            output.push_str("- *(none)*\n");
                        }
                        output.push_str("\n");

                        output.push_str("#### Assertions\n\n");
                        for a in &manifest.assertions {
                            output.push_str(&format!("- {}\n", a.label));
                        }
                        if manifest.assertions.is_empty() {
                            output.push_str("- *(none)*\n");
                        }
                        output.push_str("\n");

                        if !manifest.statuses.is_empty() {
                            output.push_str("#### Validation\n\n");
                            for (subheading, kind_key) in [
                                ("Success", "success"),
                                ("Informational", "informational"),
                                ("Failure", "failure"),
                            ] {
                                let items: Vec<_> = manifest
                                    .statuses
                                    .iter()
                                    .filter(|s| s.kind == kind_key)
                                    .collect();
                                if !items.is_empty() {
                                    output.push_str(&format!("##### {}\n\n", subheading));
                                    for status in items {
                                        output.push_str(&format!("- `{}`", status.code));
                                        if let Some(ref exp) = status.explanation {
                                            output.push_str(&format!(" — {}", exp));
                                        }
                                        output.push_str("\n");
                                    }
                                    output.push_str("\n");
                                }
                            }
                        }
                    }
                }

                if !report.warnings.is_empty() {
                    output.push_str("## Warnings\n\n");
                    for w in &report.warnings {
                        output.push_str(&format!("- {}\n", w));
                    }
                    output.push_str("\n");
                }
            }
            ReportItem::CrJsonValidation(report) => {
                output.push_str(&format!("**Asset:** {}\n\n", report.input.resolved_path));
                output.push_str("**Format:** crJSON\n\n");
                output.push_str("## Validation\n\n");
                output.push_str(&format!(
                    "- **Result:** `{}`\n",
                    if report.valid { "pass" } else { "fail" }
                ));
                if !report.messages.is_empty() {
                    output.push_str("\n**Messages:**\n\n");
                    for msg in &report.messages {
                        output.push_str(&format!("- {}\n", msg));
                    }
                }
            }
        }

        output.push_str("## Report Generation Info\n\n");
        output.push_str(&format!(
            "**Tool:** {} {}  \n**Generated:** {}\n",
            self.tool.name, self.tool.version, self.generated_at
        ));

        output
    }

    pub fn render_html(&self, profile_only: bool) -> String {
        let report_generation_info = format!(
            r#"<h2>Report Generation Info</h2><table class="info-table"><tbody><tr><th>Tool</th><td>{} {}</td></tr><tr><th>Generated</th><td>{}</td></tr></tbody></table>"#,
            html_escape(self.tool.name),
            html_escape(self.tool.version),
            html_escape(&self.generated_at)
        );

        let body = match self.results.first() {
            Some(ReportItem::Asset(report)) => render_single_asset_html(report, profile_only),
            Some(ReportItem::CrJsonValidation(report)) => render_single_crjson_html(report),
            None => String::new(),
        };

        const STYLES: &str = r#"
body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 1.5rem 2rem; background: #f5f2ed; color: #1a1a1a; max-width: 56rem; }
h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
.report-meta { color: #555; font-size: 0.875rem; }
.report-body { padding: 1rem 0; }
.report-body .report-asset { margin: 0 0 0.25rem; word-break: break-all; }
.report-body .report-format { margin: 0 0 1rem; color: #555; }
.report-body h2 { font-size: 1.1rem; margin: 1rem 0 0.5rem; }
.report-body h3 { font-size: 1rem; margin: 0.75rem 0 0.35rem; }
.badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
.badge-trusted, .badge-pass { background: #d4edda; color: #155724; }
.badge-valid { background: #cce5ff; color: #004085; }
.badge-invalid, .badge-fail { background: #f8d7da; color: #721c24; }
.badge-unknown { background: #e2e3e5; color: #383d41; }
.trust-status { margin: 0.75rem 0 1rem; padding: 0.75rem 1rem; background: #f0f4f8; border-radius: 8px; border-left: 4px solid #0d6efd; font-size: 1.05rem; }
.trust-status .badge { font-size: 0.95rem; padding: 0.35rem 0.65rem; }
.info-table { border-collapse: collapse; width: 100%; max-width: 40rem; margin: 0.35rem 0; font-size: 0.9rem; }
.info-table th { text-align: left; padding: 0.35rem 0.75rem 0.35rem 0; color: #555; font-weight: 600; width: 10rem; vertical-align: top; }
.info-table td { padding: 0.35rem 0.75rem 0.35rem 0; }
.info-table tr:nth-child(even) td { background: #f9f9f8; }
.info-table tr:nth-child(odd) td { background: #fff; }
details.manifest-details { margin: 0.5rem 0; border: 1px solid #d4c8b2; border-radius: 8px; background: #fff; overflow: hidden; }
details.manifest-details[open] { border-left: 4px solid #0d6efd; }
summary.manifest-summary { padding: 0.6rem 0.75rem; cursor: pointer; font-weight: 600; font-size: 0.95rem; background: #f9f7f4; list-style: none; }
summary.manifest-summary::-webkit-details-marker { display: none; }
summary.manifest-summary::before { content: "▶ "; font-size: 0.7rem; color: #666; }
details.manifest-details[open] summary.manifest-summary::before { content: "▼ "; }
.manifest-inner { padding: 0.75rem 1rem; border-top: 1px solid #eee; }
.manifest-inner h4 { font-size: 0.95rem; margin: 0.75rem 0 0.4rem; color: #444; }
.manifest-inner h4:first-child { margin-top: 0; }
.manifest-inner h5 { font-size: 0.9rem; margin: 0.5rem 0 0.25rem; }
.status-table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin: 0.35rem 0; }
.status-table th { text-align: left; padding: 0.4rem 0.6rem; font-weight: 600; }
.status-table td { padding: 0.4rem 0.6rem; }
.status-table .status-success { background: #d4edda; border-left: 3px solid #28a745; }
.status-table .status-informational { background: #fff3cd; border-left: 3px solid #ffc107; }
.status-table .status-failure { background: #f8d7da; border-left: 3px solid #dc3545; }
.status-emoji { font-style: normal; }
.warnings-list { margin: 0.35rem 0; }
.warnings-list li { margin: 0.25rem 0; }
.row-emoji { margin-right: 0.15rem; font-style: normal; }
"#;

        let h1 = if profile_only {
            "📝 C2PA Conformance Report"
        } else {
            "C2PA Conformance Report"
        };
        format!(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>C2PA Conformance Report</title><style>{}</style></head><body><h1>{}</h1><div class="report-body">{}{}</div></body></html>"#,
            STYLES, h1, body, report_generation_info
        )
    }
}

#[allow(dead_code)]
fn format_input_type(t: InputType) -> &'static str {
    match t {
        InputType::Asset => "asset",
        InputType::SidecarManifest => "sidecar manifest",
        InputType::CrJson => "crJSON",
    }
}

/// Partitions statuses into claim signature, signing certificate, and timestamp (C2PA validation codes).
fn partition_validation_statuses(
    statuses: &[StatusRecord],
) -> (Vec<&StatusRecord>, Vec<&StatusRecord>, Vec<&StatusRecord>) {
    let mut claim_sig = Vec::new();
    let mut signing_cert = Vec::new();
    let mut timestamp = Vec::new();
    for s in statuses {
        if s.code.starts_with("claimSignature.") {
            claim_sig.push(s);
        } else if s.code.starts_with("signingCredential.")
            || s.code.starts_with("signingCertificate.")
        {
            signing_cert.push(s);
        } else if s.code.starts_with("timeStamp.") {
            timestamp.push(s);
        }
    }
    (claim_sig, signing_cert, timestamp)
}

fn format_status_list(statuses: Vec<&StatusRecord>) -> String {
    statuses
        .iter()
        .map(|s| {
            let code = &s.code;
            let exp = s.explanation.as_deref().unwrap_or("");
            if exp.is_empty() {
                code.clone()
            } else {
                format!("{} ({})", code, exp)
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn render_state(state: ValidationState) -> &'static str {
    match state {
        ValidationState::Trusted => "trusted",
        ValidationState::Valid => "valid",
        ValidationState::Invalid => "invalid",
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn render_profile_compliance(profile_evaluation: Option<&serde_json::Value>) -> &'static str {
    match profile_compliance_value(profile_evaluation) {
        Some(true) => "pass",
        Some(false) => "fail",
        None => "unknown",
    }
}

/// Professional one-line compliance for markdown (emoji + text).
fn compliance_emoji_md(comp: &str) -> String {
    match comp {
        "pass" => "**✅ pass**".to_string(),
        "fail" => "**❌ fail**".to_string(),
        _ => format!("**⚪ {}**", comp),
    }
}

/// Emoji prefix for profile statement section titles (subtle categorization).
fn profile_section_emoji(title: &str) -> &'static str {
    match title {
        t if t.contains("Content") && t.contains("Information") => "📄 ",
        t if t.contains("Manifest") => "📦 ",
        t if t.contains("Action") => "⚙️ ",
        t if t.eq_ignore_ascii_case("Compliance") => "📊 ",
        _ => "▪️ ",
    }
}

/// Renders profile_metadata and statements from profile evaluation JSON as markdown.
fn render_profile_details_md(eval: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(meta) = eval.get("profile_metadata") {
        out.push_str("### ℹ️ Profile metadata\n\n");
        for key in ["name", "issuer", "date", "version", "language"] {
            if let Some(v) = meta.get(key).and_then(serde_json::Value::as_str) {
                out.push_str(&format!("- **{}:** {}\n", key, v));
            }
        }
        out.push_str("\n");
    }
    if let Some(sections) = eval.get("statements").and_then(serde_json::Value::as_array) {
        for section in sections {
            let items = match section.as_array() {
                Some(a) => a,
                None => continue,
            };
            let section_title = items
                .iter()
                .find(|o| o.get("title").is_some())
                .and_then(|o| o.get("title").and_then(serde_json::Value::as_str));
            if let Some(title) = section_title {
                out.push_str(&format!(
                    "### {}{}\n\n",
                    profile_section_emoji(title),
                    title
                ));
            }
            for item in items {
                if item.get("title").is_some()
                    && item.get("report_text").is_some()
                    && item.get("value").is_none()
                {
                    if let Some(t) = item.get("report_text").and_then(serde_json::Value::as_str) {
                        out.push_str(&format!("{}\n\n", t));
                    }
                    continue;
                }
                if let Some(report_text) =
                    item.get("report_text").and_then(serde_json::Value::as_str)
                {
                    let value_str = item.get("value").map(|v| match v {
                        serde_json::Value::Bool(b) => format!("{}", b),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        _ => format!("{}", v),
                    });
                    if let Some(v) = value_str {
                        let id = item
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        let row_emoji = match item.get("value") {
                            Some(serde_json::Value::Bool(true)) => "✅ ",
                            Some(serde_json::Value::Bool(false)) => "❌ ",
                            _ => "▪️ ",
                        };
                        if id.is_empty() {
                            out.push_str(&format!("- {}`{}` — {}\n", row_emoji, v, report_text));
                        } else {
                            out.push_str(&format!(
                                "- {}**{}:** `{}` — {}\n",
                                row_emoji, id, v, report_text
                            ));
                        }
                    } else {
                        out.push_str(&format!("- {}\n", report_text));
                    }
                }
            }
            out.push_str("\n");
        }
    }
    out
}

fn compliance_label_emoji(comp: &str) -> String {
    match comp {
        "pass" => "✅ pass".to_string(),
        "fail" => "❌ fail".to_string(),
        _ => format!("⚪ {}", comp),
    }
}

/// Renders profile_metadata and statements from profile evaluation JSON as HTML.
fn render_profile_details_html(eval: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(meta) = eval.get("profile_metadata") {
        out.push_str("<h3>ℹ️ Profile metadata</h3><table class=\"info-table\"><tbody>");
        for key in ["name", "issuer", "date", "version", "language"] {
            if let Some(v) = meta.get(key).and_then(serde_json::Value::as_str) {
                out.push_str(&format!(
                    "<tr><th>{}</th><td>{}</td></tr>",
                    html_escape(key),
                    html_escape(v)
                ));
            }
        }
        out.push_str("</tbody></table>");
    }
    if let Some(sections) = eval.get("statements").and_then(serde_json::Value::as_array) {
        for section in sections {
            let items = match section.as_array() {
                Some(a) => a,
                None => continue,
            };
            let section_title = items
                .iter()
                .find(|o| o.get("title").is_some())
                .and_then(|o| o.get("title").and_then(serde_json::Value::as_str));
            if let Some(title) = section_title {
                out.push_str(&format!(
                    "<h3>{}{}</h3>",
                    profile_section_emoji(title),
                    html_escape(title)
                ));
            }
            out.push_str("<table class=\"info-table\"><tbody>");
            for item in items {
                if item.get("title").is_some()
                    && item.get("report_text").is_some()
                    && item.get("value").is_none()
                {
                    if let Some(t) = item.get("report_text").and_then(serde_json::Value::as_str) {
                        out.push_str(&format!(
                            "<tr><td colspan=\"2\">{}</td></tr>",
                            html_escape(t)
                        ));
                    }
                    continue;
                }
                if let Some(report_text) =
                    item.get("report_text").and_then(serde_json::Value::as_str)
                {
                    let id = item
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let value_cell = item.get("value").map(|v| match v {
                        serde_json::Value::Bool(b) => format!(
                            r#"<span class="row-emoji" aria-hidden="true">{}</span> <span class="badge badge-{}">{}</span>"#,
                            if *b { "✅" } else { "❌" },
                            if *b { "pass" } else { "fail" },
                            b
                        ),
                        serde_json::Value::Number(n) => html_escape(&n.to_string()),
                        serde_json::Value::String(s) => html_escape(s),
                        _ => html_escape(&v.to_string()),
                    }).unwrap_or_else(|| "—".to_string());
                    out.push_str(&format!(
                        "<tr><th>{}</th><td>{} — {}</td></tr>",
                        html_escape(id),
                        value_cell,
                        html_escape(report_text)
                    ));
                }
            }
            out.push_str("</tbody></table>");
        }
    }
    out
}

fn render_single_asset_html(report: &AssetReport, profile_only: bool) -> String {
    let mut out = if profile_only {
        format!(
            r#"<p class="report-asset"><strong>📁 Asset:</strong> {}</p><p class="report-format"><strong>📄 Format:</strong> {}</p>"#,
            html_escape(&report.input.resolved_path),
            html_escape(&report.input.detected_format)
        )
    } else {
        format!(
            r#"<p class="report-asset"><strong>Asset:</strong> {}</p><p class="report-format"><strong>Format:</strong> {}</p>"#,
            html_escape(&report.input.resolved_path),
            html_escape(&report.input.detected_format)
        )
    };

    if profile_only {
        // Profile report: Profile (path, compliance, details) at top; no Validation & Trust or Manifests.
        if let Some(profile_path) = &report.profile_path {
            let badge_class = match profile_compliance_value(report.profile_evaluation.as_ref()) {
                Some(true) => "pass",
                Some(false) => "fail",
                None => "unknown",
            };
            let comp = render_profile_compliance(report.profile_evaluation.as_ref());
            out.push_str(&format!(
                r#"<h2>📝 Profile</h2><table class="info-table"><tbody><tr><th>Profile</th><td>{}</td></tr><tr><th>Compliance</th><td><span class="badge badge-{}">{}</span></td></tr></tbody></table>"#,
                html_escape(profile_path),
                badge_class,
                html_escape(&compliance_label_emoji(comp))
            ));
            if let Some(ref eval) = report.profile_evaluation {
                out.push_str(&render_profile_details_html(eval));
            }
        }
    } else {
        let state_class = match report.validation_state {
            ValidationState::Trusted => "trusted",
            ValidationState::Valid => "valid",
            ValidationState::Invalid => "invalid",
        };
        out.push_str(&format!(
            r#"<h2>Validation &amp; Trust</h2><p class="trust-status"><strong>Trust Status:</strong> <span class="badge badge-{}">{}</span></p><table class="info-table"><tbody>"#,
            state_class,
            render_state(report.validation_state)
        ));
        if !report.trust.notes.is_empty() {
            out.push_str(&format!(
                "<tr><th>Notes</th><td><ul style=\"margin:0;padding-left:1.25rem;\">{}</ul></td></tr>",
                report
                    .trust
                    .notes
                    .iter()
                    .map(|n| format!("<li>{}</li>", html_escape(n)))
                    .collect::<String>()
            ));
        }
        let (claim_sig, signing_cert, timestamp) = partition_validation_statuses(&report.statuses);
        if !claim_sig.is_empty() {
            out.push_str(&format!(
                r#"<tr><th>Claim signature</th><td>{}</td></tr>"#,
                html_escape(&format_status_list(claim_sig))
            ));
        }
        if !signing_cert.is_empty() {
            out.push_str(&format!(
                r#"<tr><th>Signing certificate</th><td>{}</td></tr>"#,
                html_escape(&format_status_list(signing_cert))
            ));
        }
        if !timestamp.is_empty() {
            out.push_str(&format!(
                r#"<tr><th>Timestamp</th><td>{}</td></tr>"#,
                html_escape(&format_status_list(timestamp))
            ));
        }
        out.push_str("</tbody></table>");

        if let Some(profile_path) = &report.profile_path {
            let badge_class = match profile_compliance_value(report.profile_evaluation.as_ref()) {
                Some(true) => "pass",
                Some(false) => "fail",
                None => "unknown",
            };
            out.push_str(&format!(
                r#"<h2>Profile</h2><table class="info-table"><tbody><tr><th>Path</th><td>{}</td></tr><tr><th>Compliance</th><td><span class="badge badge-{}">{}</span></td></tr></tbody></table>"#,
                html_escape(profile_path),
                badge_class,
                render_profile_compliance(report.profile_evaluation.as_ref())
            ));
        }

        if !report.manifests.is_empty() {
            out.push_str("<h2>Manifests</h2>");
            for (i, manifest) in report.manifests.iter().enumerate() {
                let heading = manifest
                    .title
                    .as_deref()
                    .or(manifest.label.as_deref())
                    .unwrap_or("(unnamed)");
                out.push_str(&format!(
                r#"<details class="manifest-details"><summary class="manifest-summary">Manifest {}: {}</summary><div class="manifest-inner">"#,
                i + 1,
                html_escape(heading)
            ));

                out.push_str("<h4>Claim</h4><table class=\"info-table\"><tbody>");
                if let Some(ref v) = manifest.claim_version {
                    out.push_str(&format!(
                        "<tr><th>Claim version</th><td>{}</td></tr>",
                        html_escape(v)
                    ));
                }
                if let Some(ref gen) = manifest.claim_generator {
                    out.push_str(&format!(
                        "<tr><th>Claim generator</th><td>{}</td></tr>",
                        html_escape(gen)
                    ));
                }
                if manifest.claim_version.is_none() && manifest.claim_generator.is_none() {
                    out.push_str("<tr><th>Claim</th><td><em>(none)</em></td></tr>");
                }
                out.push_str("</tbody></table>");

                out.push_str("<h4>Signature Info</h4><table class=\"info-table\"><tbody>");
                if let Some(ref sig) = manifest.signature {
                    if let Some(ref cn) = sig.common_name {
                        out.push_str(&format!(
                            "<tr><th>Signing (CN)</th><td>{}</td></tr>",
                            html_escape(cn)
                        ));
                    }
                    if let Some(ref issuer) = sig.issuer {
                        out.push_str(&format!(
                            "<tr><th>Issuer</th><td>{}</td></tr>",
                            html_escape(issuer)
                        ));
                    }
                    if let Some(ref t) = sig.time {
                        out.push_str(&format!(
                            "<tr><th>Time</th><td>{}</td></tr>",
                            html_escape(t)
                        ));
                    }
                }
                if manifest.signature.is_none() {
                    out.push_str("<tr><th>Signature</th><td><em>(none)</em></td></tr>");
                }
                out.push_str("</tbody></table>");

                out.push_str("<h4>Assertions</h4><table class=\"info-table\"><thead><tr><th>Assertion</th></tr></thead><tbody>");
                for a in &manifest.assertions {
                    out.push_str(&format!("<tr><td>{}</td></tr>", html_escape(&a.label)));
                }
                if manifest.assertions.is_empty() {
                    out.push_str("<tr><td><em>(none)</em></td></tr>");
                }
                out.push_str("</tbody></table>");

                if !manifest.statuses.is_empty() {
                    out.push_str("<h4>Validation</h4><table class=\"status-table\"><thead><tr><th>Type</th><th>Code</th><th>Details</th></tr></thead><tbody>");
                    for status in &manifest.statuses {
                        let (label, row_class) = match status.kind.as_str() {
                            "success" => ("&#x2714; Success", "status-success"), // ✓
                            "informational" => ("&#x2139; Informational", "status-informational"), // ℹ
                            _ => ("&#x2718; Failure", "status-failure"), // ✗
                        };
                        let explanation = status
                            .explanation
                            .as_deref()
                            .map(html_escape)
                            .unwrap_or_default();
                        out.push_str(&format!(
                        r#"<tr class="{}"><td class="status-emoji">{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
                        row_class,
                        label,
                        html_escape(&status.code),
                        explanation
                    ));
                    }
                    out.push_str("</tbody></table>");
                }
                out.push_str("</div></details>");
            }
        }
    }

    if !report.warnings.is_empty() {
        out.push_str("<h2>Warnings</h2><ul class=\"warnings-list\">");
        for w in &report.warnings {
            out.push_str(&format!(
                "<li><span class=\"status-emoji\" aria-hidden=\"true\">&#x26A0;</span> {}</li>",
                html_escape(w)
            ));
        }
        out.push_str("</ul>");
    }

    out
}

fn render_single_crjson_html(report: &CrJsonValidationReport) -> String {
    let mut out = format!(
        r#"<p class="report-asset"><strong>Asset:</strong> {}</p><p class="report-format"><strong>Format:</strong> crJSON</p><h2>Validation</h2><p><span class="badge badge-{}">{}</span></p>"#,
        html_escape(&report.input.resolved_path),
        if report.valid { "pass" } else { "fail" },
        if report.valid { "pass" } else { "fail" }
    );
    if !report.messages.is_empty() {
        out.push_str("<ul>");
        for m in &report.messages {
            out.push_str(&format!("<li>{}</li>", html_escape(m)));
        }
        out.push_str("</ul>");
    }
    out
}

fn profile_compliance_value(profile_evaluation: Option<&serde_json::Value>) -> Option<bool> {
    let statements = profile_evaluation?.get("statements")?.as_array()?;
    for section in statements {
        let section_items = section.as_array()?;
        for item in section_items {
            if item.get("id").and_then(serde_json::Value::as_str) == Some("c2pa:profile_compliance")
            {
                return item.get("value").and_then(serde_json::Value::as_bool);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_summary(
        total: usize,
        trusted: usize,
        valid: usize,
        invalid: usize,
        errors: usize,
    ) -> Summary {
        Summary {
            total,
            trusted,
            valid,
            invalid,
            errors,
            warnings: 0,
        }
    }

    fn sample_input_descriptor(path: &str, input_type: InputType) -> InputDescriptor {
        InputDescriptor {
            original: path.to_string(),
            resolved_path: path.to_string(),
            input_type,
            detected_format: "image/jpeg".to_string(),
        }
    }

    #[test]
    fn exit_code_failure_when_invalid_or_errors() {
        let report = CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: "test",
                version: "0.0.0",
                c2pa_sdk: SdkMetadata {
                    name: "c2pa",
                    version: "0.0.0",
                    source: "test",
                },
            },
            generated_at: "0".to_string(),
            summary: sample_summary(1, 0, 0, 1, 0),
            results: vec![],
        };
        assert_eq!(report.exit_code(), ExitCode::FAILURE);
    }

    #[test]
    fn exit_code_failure_when_errors() {
        let report = CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: "test",
                version: "0.0.0",
                c2pa_sdk: SdkMetadata {
                    name: "c2pa",
                    version: "0.0.0",
                    source: "test",
                },
            },
            generated_at: "0".to_string(),
            summary: sample_summary(1, 0, 0, 0, 1),
            results: vec![],
        };
        assert_eq!(report.exit_code(), ExitCode::FAILURE);
    }

    #[test]
    fn exit_code_success_when_trusted_or_valid_only() {
        let report = CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: "test",
                version: "0.0.0",
                c2pa_sdk: SdkMetadata {
                    name: "c2pa",
                    version: "0.0.0",
                    source: "test",
                },
            },
            generated_at: "0".to_string(),
            summary: sample_summary(1, 1, 0, 0, 0),
            results: vec![],
        };
        assert_eq!(report.exit_code(), ExitCode::SUCCESS);
    }

    #[test]
    fn render_markdown_includes_summary_and_section() {
        let report = CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: "test",
                version: "0.0.0",
                c2pa_sdk: SdkMetadata {
                    name: "c2pa",
                    version: "0.0.0",
                    source: "test",
                },
            },
            generated_at: "0".to_string(),
            summary: sample_summary(2, 1, 1, 0, 0),
            results: vec![ReportItem::CrJsonValidation(CrJsonValidationReport {
                input: sample_input_descriptor("/path/to/file.json", InputType::CrJson),
                valid: true,
                messages: vec!["ok".to_string()],
                rubric_results: Vec::new(),
            })],
        };
        let md = report.render_markdown(false);
        assert!(md.starts_with("# C2PA Conformance Report"));
        assert!(md.contains("## Validation"));
        assert!(md.contains("**Result:** `pass`"));
        assert!(md.contains("## Report Generation Info"));
    }

    #[test]
    fn render_html_includes_doctype_and_escapes_content() {
        let report = CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: "test",
                version: "0.0.0",
                c2pa_sdk: SdkMetadata {
                    name: "c2pa",
                    version: "0.0.0",
                    source: "test",
                },
            },
            generated_at: "0".to_string(),
            summary: sample_summary(0, 0, 0, 0, 0),
            results: vec![ReportItem::CrJsonValidation(CrJsonValidationReport {
                input: sample_input_descriptor("/path/to/file&name.json", InputType::CrJson),
                valid: false,
                messages: vec![],
                rubric_results: Vec::new(),
            })],
        };
        let html = report.render_html(false);
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("<h1>C2PA Conformance Report</h1>"));
        assert!(
            html.contains("file&amp;name.json"),
            "ampersand should be escaped"
        );
        assert!(html.contains("badge-fail"));
        assert!(html.contains("report-body"));
    }
}
