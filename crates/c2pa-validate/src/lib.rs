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

pub mod cli;
pub mod report;
pub mod validator;

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value as JsonValue;
use tracing::Level;

use crate::{
    cli::{Cli, OutputFormat},
    report::{CrJsonReport, ReportItem},
    validator::Validator,
};

pub fn run() -> ExitCode {
    match try_run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the validator with the given CLI args (for tests or programmatic use).
pub fn run_with_cli(cli: Cli) -> ExitCode {
    match try_run_with_cli(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn try_run() -> Result<ExitCode> {
    let cli = Cli::parse();
    try_run_with_cli(cli)
}

fn try_run_with_cli(cli: Cli) -> Result<ExitCode> {
    init_tracing(cli.verbose)?;

    let validator = Validator::new(cli.clone())?;
    let report = validator.run()?;

    let asset_count = report
        .results
        .iter()
        .filter(|r| matches!(r, ReportItem::Asset(_)))
        .count();
    let multiple_assets_structured = is_structured_format(cli.format) && asset_count > 1;

    if multiple_assets_structured {
        let out_dir = cli
            .output
            .as_ref()
            .map(|p| resolve_output_dir(p))
            .transpose()?;
        write_structured_per_asset(
            &report,
            out_dir.as_deref(),
            cli.format,
            cli.profile.is_some(),
        )?;
    } else {
        let use_profile = cli.profile.is_some();
        if use_profile {
            // Always write both crJSON and profile evaluation when a profile is used.
            let report_path = match cli.output.as_ref() {
                Some(output) => resolve_output_path(output, cli.format, &report, true)?,
                None => default_output_path(cli.format, &report, true)?,
            };
            let crjson_path = crjson_output_path(cli.format, &report, &report_path)?;
            if let Some(parent) = report_path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create output directory {}", parent.display())
                })?;
            }
            let rendered_crjson =
                render_report(&report, cli.format, false).context("failed to render crJSON")?;
            let rendered_profile = render_report(&report, cli.format, true)
                .context("failed to render profile report")?;
            fs::write(&crjson_path, rendered_crjson)
                .with_context(|| format!("failed to write crJSON to {}", crjson_path.display()))?;
            fs::write(&report_path, rendered_profile).with_context(|| {
                format!(
                    "failed to write profile report to {}",
                    report_path.display()
                )
            })?;
        } else {
            let rendered = render_report(&report, cli.format, false)?;
            let path = match cli.output.as_ref() {
                Some(output) => resolve_output_path(output, cli.format, &report, false)?,
                None => default_output_path(cli.format, &report, false)?,
            };
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create output directory {}", parent.display())
                })?;
            }
            fs::write(&path, rendered)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
        }
    }

    Ok(report.exit_code())
}

fn init_tracing(verbose: u8) -> Result<()> {
    let level = match verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        _ => Level::DEBUG,
    };

    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .without_time()
        .try_init(); // ignore "already initialized" when run_with_cli is used from multiple tests

    Ok(())
}

fn is_structured_format(format: OutputFormat) -> bool {
    matches!(format, OutputFormat::Json | OutputFormat::Yaml)
}

fn render_report(
    report: &CrJsonReport,
    format: OutputFormat,
    use_profile_output: bool,
) -> Result<String> {
    match format {
        OutputFormat::Json => {
            let structured_value = report_to_structured_value(report, use_profile_output);
            serde_json::to_string_pretty(&structured_value).context("failed to render JSON output")
        }
        OutputFormat::Yaml => {
            let structured_value = report_to_structured_value(report, use_profile_output);
            serde_yaml::to_string(&structured_value).context("failed to render YAML output")
        }
        OutputFormat::Markdown => Ok(report.render_markdown(use_profile_output)),
        OutputFormat::Html => Ok(report.render_html(use_profile_output)),
    }
}

/// Structured output is either reader crJSON, profile evaluation, or rubric
/// results: one object for a single asset, or null for none.
fn report_to_structured_value(report: &CrJsonReport, use_profile_output: bool) -> JsonValue {
    let values: Vec<JsonValue> = report
        .results
        .iter()
        .filter_map(|r| match r {
            ReportItem::Asset(asset) => structured_asset_value(asset, use_profile_output),
            ReportItem::CrJsonValidation(crjson_report) => structured_crjson_value(crjson_report),
        })
        .collect();
    match values.len() {
        0 => JsonValue::Null,
        1 => values.into_iter().next().unwrap_or(JsonValue::Null),
        _ => JsonValue::Array(values), // unused when multiple (we write per-file)
    }
}

fn structured_crjson_value(report: &crate::report::CrJsonValidationReport) -> Option<JsonValue> {
    if report.rubric_results.is_empty() {
        return Some(serde_json::to_value(report).ok()?);
    }
    // When rubric results are present, return them directly. For a single
    // rubric, return the result object; for multiple, return an array.
    match report.rubric_results.len() {
        1 => Some(report.rubric_results[0].clone()),
        _ => Some(JsonValue::Array(report.rubric_results.clone())),
    }
}

fn structured_asset_value(
    asset: &crate::report::AssetReport,
    use_profile_output: bool,
) -> Option<JsonValue> {
    if use_profile_output {
        asset.profile_evaluation.clone()
    } else {
        asset.reader_json.clone()
    }
}

/// Resolve -o to a directory for multi-file structured output. Errors if path looks like a single file.
fn resolve_output_dir(output: &Path) -> Result<PathBuf> {
    let looks_like_file = output
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            n.ends_with(".json")
                || n.ends_with(".yaml")
                || n.ends_with(".yml")
                || n.ends_with(".md")
                || n.ends_with(".html")
        });
    if looks_like_file && !output.is_dir() {
        anyhow::bail!(
            "With multiple inputs and structured output, use -o <directory> to write one file per input (e.g. -o ./out)"
        );
    }
    fs::create_dir_all(output)
        .with_context(|| format!("failed to create output directory {}", output.display()))?;
    Ok(output.to_path_buf())
}

/// Write one structured file per asset. When `out_dir` is Some, all files go there (stems get _2, _3 on collision).
/// When None, each file is written next to its source in the same directory.
/// When a profile is used, writes both crJSON (stem.ext) and profile evaluation (stem_report.ext) per asset.
fn write_structured_per_asset(
    report: &CrJsonReport,
    out_dir: Option<&Path>,
    format: OutputFormat,
    use_profile_output: bool,
) -> Result<()> {
    let mut stem_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let extension = format_extension(format);
    for r in &report.results {
        if let ReportItem::Asset(asset) = r {
            let resolved = Path::new(&asset.input.resolved_path);
            let stem = resolved
                .file_stem()
                .and_then(|s| s.to_os_string().into_string().ok())
                .unwrap_or_else(|| "report".to_string());
            let (dir, count_key) = match out_dir {
                Some(d) => (d.to_path_buf(), stem.clone()),
                None => (
                    resolved
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_default(),
                    format!(
                        "{}::{}",
                        resolved.parent().unwrap_or(Path::new(".")).display(),
                        stem
                    ),
                ),
            };
            let count = stem_counts.entry(count_key).or_insert(0);
            *count += 1;
            let name_suffix = if *count == 1 {
                String::new()
            } else {
                format!("_{}", count)
            };

            let write_value = |value: &JsonValue, name_base: &str| -> Result<()> {
                let filename = format!("{name_base}{name_suffix}.{extension}");
                let path = dir.join(&filename);
                fs::create_dir_all(&dir)
                    .with_context(|| format!("failed to create output dir {}", dir.display()))?;
                let rendered = match format {
                    OutputFormat::Json => serde_json::to_string_pretty(value)
                        .context("failed to render JSON output")?,
                    OutputFormat::Yaml => {
                        serde_yaml::to_string(value).context("failed to render YAML output")?
                    }
                    OutputFormat::Markdown | OutputFormat::Html => {
                        unreachable!("structured formats only")
                    }
                };
                fs::write(&path, rendered)
                    .with_context(|| format!("failed to write {}", path.display()))?;
                Ok(())
            };

            if use_profile_output {
                if let Some(crjson) = structured_asset_value(asset, false) {
                    write_value(&crjson, &stem)?;
                }
                if let Some(profile_value) = structured_asset_value(asset, true) {
                    write_value(&profile_value, &format!("{stem}_report"))?;
                }
            } else if let Some(value) = structured_asset_value(asset, false) {
                let name_base = stem.clone();
                write_value(&value, &name_base)?;
            }
        }
    }
    Ok(())
}

fn format_extension(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Json => "json",
        OutputFormat::Yaml => "yaml",
        OutputFormat::Markdown => "md",
        OutputFormat::Html => "html",
    }
}

/// Path for the crJSON file when writing both crJSON and profile report: same directory as report_path, stem from first asset.
fn crjson_output_path(
    format: OutputFormat,
    report: &CrJsonReport,
    report_path: &Path,
) -> Result<PathBuf> {
    let ext = format_extension(format);
    let stem = report
        .results
        .first()
        .and_then(|r| {
            Path::new(r.input_path())
                .file_stem()
                .and_then(|s| s.to_os_string().into_string().ok())
        })
        .unwrap_or_else(|| "report".to_string());
    let parent = report_path.parent().unwrap_or(Path::new("."));
    Ok(parent.join(format!("{stem}.{ext}")))
}

/// When -o is not given, default to the same directory as the (first) source file, with stem + format extension.
/// For profile evaluation output, the filename is stem_report.ext.
fn default_output_path(
    format: OutputFormat,
    report: &CrJsonReport,
    use_profile_output: bool,
) -> Result<PathBuf> {
    let ext = format_extension(format);
    let (parent, base) = report
        .results
        .first()
        .map(|r| {
            let p = Path::new(r.input_path());
            let parent = p.parent().unwrap_or(Path::new(".")).to_path_buf();
            let stem = p
                .file_stem()
                .and_then(|s| s.to_os_string().into_string().ok())
                .unwrap_or_else(|| "report".to_string());
            let base = if use_profile_output {
                format!("{stem}_report")
            } else {
                stem
            };
            (parent, base)
        })
        .unwrap_or_else(|| (PathBuf::from("."), "report".to_string()));
    Ok(parent.join(format!("{base}.{ext}")))
}

/// Treats -o as a directory when it is an existing directory or has no format extension.
/// When treated as a directory, creates it if needed and chooses a filename from the source file(s).
/// For profile evaluation output, the filename is stem_report.ext.
fn resolve_output_path(
    output: &Path,
    format: OutputFormat,
    report: &CrJsonReport,
    use_profile_output: bool,
) -> Result<PathBuf> {
    let ext = format_extension(format);
    let is_output_dir = output.is_dir()
        || !output
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.ends_with(".json")
                    || n.ends_with(".yaml")
                    || n.ends_with(".yml")
                    || n.ends_with(".md")
                    || n.ends_with(".html")
            });

    if is_output_dir {
        fs::create_dir_all(output)
            .with_context(|| format!("failed to create output dir {}", output.display()))?;
        let stem = if report.results.len() == 1 {
            report
                .results
                .first()
                .and_then(|r| {
                    Path::new(r.input_path())
                        .file_stem()
                        .and_then(|s| s.to_os_string().into_string().ok())
                })
                .unwrap_or_else(|| "report".to_string())
        } else {
            "report".to_string()
        };
        let base = if use_profile_output {
            format!("{stem}_report")
        } else {
            stem
        };
        Ok(output.join(format!("{base}.{ext}")))
    } else {
        Ok(output.to_path_buf())
    }
}

pub fn normalize_output_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.map(|candidate| {
        if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(candidate)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_output_path_none_returns_none() {
        assert!(normalize_output_path(None).is_none());
    }

    #[test]
    fn normalize_output_path_absolute_returns_unchanged() {
        let abs = PathBuf::from("/tmp/out.json");
        assert_eq!(normalize_output_path(Some(abs.clone())), Some(abs));
    }

    #[test]
    fn normalize_output_path_relative_joins_cwd() {
        let rel = PathBuf::from("out.json");
        let result = normalize_output_path(Some(rel));
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.is_absolute() || result.to_string_lossy().starts_with("out"));
    }
}
