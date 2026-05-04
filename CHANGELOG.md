# Changelog

## 0.5.0

### Changed

- **Moved `$argN` injection from json-formula-rs to profile-evaluator-rs.** Parameterized named expressions (`$arg0`, `$arg1`, ...) are now handled in the evaluator layer. The evaluator compiles the AST, registers a custom function via `register_function()`, and injects `$argN` values into interpreter globals with save/restore semantics. This matches the Python reference evaluator's `_build_engine()` pattern and keeps json-formula-rs upstream-compatible.

- **Moved bare-keyword normalization from json-formula-rs to profile-evaluator-rs.** The `normalize_expression()` function that rewrote bare `true`/`false`/`null` to `true()`/`false()`/`null()` now runs at expression registration time in the evaluator, not inside the formula engine. This is a safety net for rubric files that have not yet been fixed upstream (see [c2pa-org/conformance#366](https://github.com/c2pa-org/conformance/pull/366)).

- **Reverted json-formula-rs to upstream-compatible state.** Removed `normalize_expression()`, `arg_count()`, `$argN` injection in `register_expression()`, and all associated tests. Reverted `pub globals` to private. The only additions over upstream are `register_function()`, `globals_mut()`, and expanded public exports (`FunctionEntry`, `SignatureArg`, `AstNode`, `Interpreter`, `DataType`, `JfValue`).

### Fixed

- **`ii2i` conformance golden test now matches the reference evaluator.** The `no_unsupported_assertions` trait previously deviated from the golden file because a bare `true` keyword in the rubric expression was treated as a field reference. Evaluator-layer normalization fixes this.

## 0.4.0

- Rubric evaluation engine with conformance and signals modes
- crJSON extraction and pre-existing crJSON evaluation
- Per-manifest signal detection across provenance chains
- Untrusted asset fallback for self-signed certificates
- Certificate profile validation against C2PA schemas
- Security patches for rustls-webpki, rustls, rand
- 29 signed test assets across all C2PA-supported formats

## 0.3.0

- Initial fork with validation CLI and trust list support
