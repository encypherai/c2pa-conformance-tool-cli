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

use std::{fmt, path::PathBuf};

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Parser)]
#[command(
    author,
    version,
    about = "Validate C2PA assets, sidecar manifests, and crJSON reports",
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(
        value_name = "INPUT",
        help = "Files or glob patterns to validate. Supports media assets, .c2pa sidecars, and crJSON reports."
    )]
    pub inputs: Vec<String>,

    #[arg(
        short,
        long,
        value_name = "FILE_OR_DIR",
        help = "Output file or directory. If omitted, writes next to each source (e.g. photo.jpg → photo.json in same dir)"
    )]
    pub output: Option<PathBuf>,

    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    #[arg(
        long,
        value_name = "FILE",
        help = "Path to a YAML profile to evaluate against each asset's crJSON indicators"
    )]
    pub profile: Option<PathBuf>,

    #[arg(
        short = 't',
        long,
        value_enum,
        default_value_t = TrustMode::Default,
        help = "Trust list mode: default (official C2PA list only), itl (official then ITL), or custom (requires --trust-list)"
    )]
    pub trust_mode: TrustMode,

    #[arg(
        long,
        value_name = "FILE_OR_URL",
        help = "Path or URL to a trust list (PEM). Required when --trust-mode is custom. Use --settings for advanced trust config."
    )]
    pub trust_list: Option<String>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Overlay c2pa-rs settings from JSON or TOML"
    )]
    pub settings: Option<PathBuf>,

    #[arg(long, help = "Fail on warnings, not only invalid assets")]
    pub strict: bool,

    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    // ---- Rubric evaluation flags ----
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to a rubric YAML file to evaluate against crJSON"
    )]
    pub rubric: Option<PathBuf>,

    #[arg(
        long,
        value_name = "DIR",
        help = "Directory of rubric YAML files; evaluates all against each input"
    )]
    pub rubric_dir: Option<PathBuf>,

    #[arg(
        long,
        value_enum,
        default_value_t = RubricMode::Conformance,
        help = "Rubric evaluation mode: conformance (whole-crJSON) or signals (per-manifest)"
    )]
    pub rubric_mode: RubricMode,

    #[arg(
        long,
        help = "Extract crJSON from binary assets and write to output without rubric evaluation"
    )]
    pub emit_crjson: bool,

    #[arg(
        long,
        help = "Treat inputs as pre-existing crJSON files for rubric evaluation (skips c2pa-rs reading)"
    )]
    pub crjson: bool,

    #[arg(long, help = "Fail rubric evaluation if any trait in the rubric fails")]
    pub rubric_strict: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Markdown,
    Html,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum RubricMode {
    /// Evaluate rubric against the whole crJSON document (conformance checks)
    Conformance,
    /// Evaluate rubric per-manifest for signal detection
    Signals,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum TrustMode {
    /// Official C2PA trust list only
    Default,
    /// Official list first, then ITL list
    Itl,
    /// Custom trust list (requires --trust-list)
    Custom,
}

impl fmt::Display for TrustMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Default => "default",
            Self::Itl => "itl",
            Self::Custom => "custom",
        };
        f.write_str(value)
    }
}
