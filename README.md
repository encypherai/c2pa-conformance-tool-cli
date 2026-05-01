# c2pa-conformance-tool-cli

A Rust CLI for validating C2PA media assets, evaluating conformance rubrics, and detecting provenance signals. Built on [c2pa-rs](https://github.com/contentauth/c2pa-rs), this tool validates signed assets against trust lists, evaluates asset profiles, and runs composable YAML rubrics that test conformance traits and signal detection across manifest chains.

This is the [Encypher](https://encypher.com) fork of [contentauth/c2pa-conformance-tool-cli](https://github.com/contentauth/c2pa-conformance-tool-cli), adding rubric evaluation, signals analysis, untrusted asset support, and security patches.

## What it does

**Validation** - Read C2PA manifests from binary assets, sidecar `.c2pa` files, or crJSON reports. Verify signatures, hash bindings, timestamps, and trust chain against configurable trust lists.

**Rubric evaluation** - Evaluate composable YAML rubrics against an asset's crJSON representation. Rubrics define traits (boolean expressions over crJSON fields) grouped by category. Two evaluation modes:

- **Conformance mode** evaluates the rubric against the whole crJSON document (structural correctness, deprecated assertions, trust status, claim constraints)
- **Signals mode** evaluates the rubric per-manifest, detecting inception signals (capture, GenAI, composite) and transformation signals (editorial AI, non-editorial) across the full provenance chain

**Profile evaluation** - Evaluate YAML profiles (legacy format from upstream) against each asset's crJSON indicators.

## Supported formats

The tool validates any format supported by c2pa-rs:

| Category | Formats |
|-|-|
| Image | JPEG, PNG, WebP, AVIF, DNG, GIF, HEIC, HEIF, SVG, TIFF |
| Video | MP4, MOV, AVI, M4V |
| Audio | AAC/M4A, MP3, WAV |
| Document | PDF |

For formats where c2pa-rs lacks codec support (FLAC, DOCX, EPUB, ODT, OXPS, OTF, JXL), use `-crjson` mode with pre-extracted crJSON files.

## Installation

### From source

```bash
git clone https://github.com/encypherai/c2pa-conformance-tool-cli.git
cd c2pa-conformance-tool-cli
cargo build -release
```

The binary is at `target/release/c2pa-validate`.

### Verify the build

```bash
cargo test -release - -include-ignored
```

This runs 110+ tests including golden fixture tests for conformance and signals rubrics.

## Quick start

Validate a signed image against the default C2PA trust list:

```bash
c2pa-validate image.jpg
```

Evaluate conformance rubrics against a signed asset:

```bash
c2pa-validate -rubric testfiles/rubrics/asset-rubric-conformance0.1-spec2.2.yml image.jpg
```

Detect provenance signals across a manifest chain:

```bash
c2pa-validate -rubric testfiles/rubrics/asset-rubric-signals-local.yml -rubric-mode signals image.jpg
```

Evaluate a pre-extracted crJSON file (for formats c2pa-rs cannot read):

```bash
c2pa-validate -crjson -rubric testfiles/rubrics/asset-rubric-conformance0.1-spec2.2.yml asset_crjson.json
```

Extract crJSON from a binary asset without rubric evaluation:

```bash
c2pa-validate -emit-crjson -o asset_crjson.json image.jpg
```

## Usage

```
c2pa-validate [OPTIONS] [INPUT]...
```

### Core options

| Option | Description |
|-|-|
| `INPUT...` | Files or glob patterns to validate |
| `-o, -output FILE_OR_DIR` | Output file or directory |
| `-f, -format json\|yaml\|markdown\|html` | Output format (default: json) |
| `-strict` | Fail on warnings, not only invalid assets |
| `-v, -verbose` | Increase verbosity (repeat for debug) |

### Trust options

| Option | Description |
|-|-|
| `-t, -trust-mode default\|itl\|custom` | Trust list mode |
| `-trust-list FILE_OR_URL` | PEM trust list (required for `custom` mode) |
| `-settings FILE` | Overlay c2pa-rs settings (JSON/TOML) |

### Rubric options

| Option | Description |
|-|-|
| `-rubric FILE` | YAML rubric file to evaluate against crJSON |
| `-rubric-dir DIR` | Directory of rubric YAML files; evaluates all |
| `-rubric-mode conformance\|signals` | Evaluation mode (default: conformance) |
| `-rubric-strict` | Fail if any rubric trait evaluates to false |
| `-crjson` | Treat inputs as pre-existing crJSON files |
| `-emit-crjson` | Extract crJSON from binary assets and write to output |

### Profile options

| Option | Description |
|-|-|
| `-profile FILE` | YAML profile to evaluate against each asset's crJSON |

## Trust list modes

- **`default`** - Official [C2PA Conformance Trust List](https://c2pa.org/conformance) only
- **`itl`** - Official list first, then the Interim Trust List
- **`custom`** - Your own PEM trust list (requires `-trust-list`)

When rubric evaluation is requested and all trust scenarios fail (e.g., self-signed certificates from pre-conformant products), the tool falls back to untrusted extraction. The crJSON is still produced and evaluated; the `trusted_success` trait reflects the trust failure.

## Rubric system

Rubrics are composable YAML files that define boolean traits evaluated against crJSON. Each trait has:

- A `formula`: a [JMESPath-like expression](https://jmespath.org/) over the crJSON document
- A `reportText`: human-readable description when the trait passes
- An optional `failText`: description when the trait fails

### Included rubrics

| File | Purpose |
|-|-|
| `asset-rubric-conformance0.1-spec2.2.yml` | C2PA Spec 2.2 conformance (16 traits) |
| `asset-rubric-conformance0.2-spec2.2.yml` | Updated conformance (17 traits) |
| `asset-rubric-conformance0.2-spec2.4.yml` | C2PA Spec 2.4 conformance (24 traits) |
| `asset-rubric-signals-local.yml` | Signal detection (13 trait categories) |
| `asset-rubric-integrity.yml` | Integrity verification traits |

### Conformance rubric traits

Conformance rubrics check structural correctness of the active manifest:

- `well_formed_data_present` / `well_formed_success` - Validation results exist and contain no structural failures
- `valid_data_present` / `valid_success` - Integrity validation present with no hash mismatches
- `trusted_data_present` / `trusted_success` - Trust validation present with signing credential trusted
- `active_manifest_urn` - Active manifest uses standard `urn:c2pa:` prefix
- `no_deprecated_assertions` / `no_deprecated_actions` - No use of deprecated C2PA assertions or actions
- `inception_action_position` - Inception action is first in the first created actions assertion
- `ingredient_relationship_values` - All ingredients have valid relationship values
- `update_manifest_constraints` - Update manifest constraints satisfied

### Signals rubric output

Signals mode produces per-manifest context including:

- `assertedBy` - Identity from the signing certificate (CN, O, OU fields)
- `mimeType` - Media type derived from parent ingredient references
- `allActionsIncluded` - Whether the manifest claims completeness of its action list
- `ingredients` - Resolved ingredient references with manifest indices and relationships
- `localInceptions` - Detected inception signals (capture, GenAI, composite, unknown provenance)
- `localTransformations` - Detected transformation signals (editorial AI, non-editorial edits)

## Test assets

The `testfiles/encypher-assets/` directory contains 29 signed test assets across all C2PA-supported media formats, each with a companion Reader JSON file. For 7 formats where c2pa-rs lacks native codec support (FLAC, DOCX, EPUB, ODT, OXPS, OTF, JXL), pre-converted crJSON files are included for rubric evaluation via `-crjson` mode.

## Workspace structure

```
c2pa-conformance-tool-cli/
  crates/
    c2pa-validate/          # Main CLI crate
  vendor/
    c2pa-rs/                # Vendored C2PA SDK (c2pa v0.78.0)
    profile-evaluator-rs/   # Rubric + profile evaluation engine
    json-formula-rs/        # JMESPath-like expression evaluator
  testfiles/
    rubrics/                # Rubric YAML files and golden fixtures
    encypher-assets/        # 29 signed test assets across all formats
    profiles/               # Legacy profile YAML files
    samples/                # Upstream sample assets
```

## Differences from upstream

This fork adds the following to [contentauth/c2pa-conformance-tool-cli](https://github.com/contentauth/c2pa-conformance-tool-cli):

- **Rubric evaluation engine** - `-rubric`, `-rubric-dir`, `-rubric-mode`, `-rubric-strict` flags for composable YAML rubric evaluation in conformance and signals modes
- **crJSON extraction** - `-emit-crjson` to extract crJSON from binary assets; `-crjson` to evaluate pre-existing crJSON files
- **Signals analysis** - Per-manifest signal detection (inception and transformation signals) with ingredient resolution across manifest chains
- **Untrusted asset support** - Automatic fallback to `verify_trust: false` when trust verification fails, enabling rubric evaluation on assets signed with certificates not yet in a trust list
- **Security patches** - Bumped `rustls-webpki` (3 CVEs), `rustls`, and `rand` to patched versions
- **29 test assets** - Signed conformance test assets across all supported C2PA media formats
- **110+ tests** - Golden fixture tests for conformance and signals rubrics, integration tests for all CLI modes

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
