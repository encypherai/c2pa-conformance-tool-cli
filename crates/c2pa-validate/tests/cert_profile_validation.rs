// Integration tests for cert profile validation against C2PA certificate
// profile JSON schemas.
//
// These tests require test certificates in testfiles/c2pa-cert-schemas/test-certs/.
// The directory is .gitignored because the certificates are generated from a
// private CA.  To run these tests:
//
//   1. Generate certificates for each profile (root, issuing CA, leaf, OCSP)
//      and place them as PEM files in testfiles/c2pa-cert-schemas/test-certs/
//      named: test-root.pem, test-issuing.pem, test-leaf.pem, test-ocsp.pem
//   2. Run: cargo test --release --test cert_profile_validation -- --include-ignored

use std::path::Path;

use c2pa_validate::cert_profile;

const SCHEMA_DIR: &str = "../../testfiles/c2pa-cert-schemas";
const CERT_DIR: &str = "../../testfiles/c2pa-cert-schemas/test-certs";

fn schema_path(name: &str) -> std::path::PathBuf {
    Path::new(SCHEMA_DIR).join(name)
}

fn cert_path(name: &str) -> std::path::PathBuf {
    Path::new(CERT_DIR).join(name)
}

// ---------------------------------------------------------------------------
// Schema loading (always runs - schemas are committed)
// ---------------------------------------------------------------------------

#[test]
fn schemas_load_successfully() {
    for name in [
        "rootCA.cert.schema.json",
        "claimSigningIssuingCA.cert.schema.json",
        "claimSigningLeaf.al1.cert.schema.json",
        "ocspResponderLeaf.cert.schema.json",
    ] {
        let result = cert_profile::load_schema(&schema_path(name));
        assert!(result.is_ok(), "failed to load schema {name}: {:?}", result.err());
    }
}

// ---------------------------------------------------------------------------
// Happy path: each cert type validates against its schema
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn root_ca_passes_root_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-root.pem"),
        &schema_path("rootCA.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        result.passed,
        "root CA should pass root schema, errors: {:?}",
        result.errors
    );
}

#[test]
#[ignore]
fn issuing_ca_passes_issuing_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-issuing.pem"),
        &schema_path("claimSigningIssuingCA.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        result.passed,
        "issuing CA should pass issuing schema, errors: {:?}",
        result.errors
    );
}

#[test]
#[ignore]
fn leaf_passes_leaf_al1_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-leaf.pem"),
        &schema_path("claimSigningLeaf.al1.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        result.passed,
        "leaf cert should pass leaf AL1 schema, errors: {:?}",
        result.errors
    );
}

#[test]
#[ignore]
fn ocsp_passes_ocsp_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-ocsp.pem"),
        &schema_path("ocspResponderLeaf.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        result.passed,
        "OCSP cert should pass OCSP schema, errors: {:?}",
        result.errors
    );
}

// ---------------------------------------------------------------------------
// Negative tests: wrong cert vs wrong schema
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn root_ca_fails_leaf_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-root.pem"),
        &schema_path("claimSigningLeaf.al1.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        !result.passed,
        "root CA should NOT pass leaf schema"
    );
}

#[test]
#[ignore]
fn leaf_fails_root_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-leaf.pem"),
        &schema_path("rootCA.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        !result.passed,
        "leaf cert should NOT pass root schema"
    );
}

#[test]
#[ignore]
fn ocsp_fails_leaf_schema() {
    let result = cert_profile::validate_cert_profile(
        &cert_path("test-ocsp.pem"),
        &schema_path("claimSigningLeaf.al1.cert.schema.json"),
    )
    .expect("validation failed");
    assert!(
        !result.passed,
        "OCSP cert should NOT pass leaf schema"
    );
}

// ---------------------------------------------------------------------------
// cert_to_json: structural checks
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn cert_json_has_required_top_level_fields() {
    let json = cert_profile::cert_to_json(&cert_path("test-leaf.pem"))
        .expect("cert_to_json failed");
    assert_eq!(json["format"], "certificate");
    assert!(json["decoded"].is_object());
    assert!(json["raw_hex"].is_string());
}

#[test]
#[ignore]
fn cert_json_tbs_has_extensions() {
    let json = cert_profile::cert_to_json(&cert_path("test-leaf.pem"))
        .expect("cert_to_json failed");
    let extensions = json["decoded"]["tbsCertificate"]["extensions"]
        .as_array()
        .expect("extensions should be an array");
    assert!(
        extensions.len() >= 6,
        "leaf cert should have at least 6 extensions, got {}",
        extensions.len()
    );
}

#[test]
#[ignore]
fn cert_json_c2pa_assurance_level_decoded() {
    let json = cert_profile::cert_to_json(&cert_path("test-leaf.pem"))
        .expect("cert_to_json failed");
    let extensions = json["decoded"]["tbsCertificate"]["extensions"]
        .as_array()
        .expect("extensions array");
    let al_ext = extensions
        .iter()
        .find(|e| e["extnID"]["oid"] == "1.3.6.1.4.1.62558.3")
        .expect("assurance level extension should be present");
    assert_eq!(
        al_ext["extnValue"]["_pyasn1_decoded"]["_asn1_type"],
        "ObjectIdentifier"
    );
    assert_eq!(
        al_ext["extnValue"]["_pyasn1_decoded"]["value"],
        "1.3.6.1.4.1.62558.3.10"
    );
}

#[test]
#[ignore]
fn cert_json_c2pa_cpl_record_decoded() {
    let json = cert_profile::cert_to_json(&cert_path("test-leaf.pem"))
        .expect("cert_to_json failed");
    let extensions = json["decoded"]["tbsCertificate"]["extensions"]
        .as_array()
        .expect("extensions array");
    let cpl_ext = extensions
        .iter()
        .find(|e| e["extnID"]["oid"] == "1.3.6.1.4.1.62558.4")
        .expect("CPL record extension should be present");
    assert_eq!(
        cpl_ext["extnValue"]["_pyasn1_decoded"]["_asn1_type"],
        "UTF8String"
    );
    let cpl_value = cpl_ext["extnValue"]["_pyasn1_decoded"]["value"]
        .as_str()
        .expect("CPL value should be a string");
    assert_eq!(cpl_value.len(), 36, "CPL record ID should be a UUID (36 chars)");
}

#[test]
#[ignore]
fn cert_json_eku_contains_c2pa_oid() {
    let json = cert_profile::cert_to_json(&cert_path("test-leaf.pem"))
        .expect("cert_to_json failed");
    let extensions = json["decoded"]["tbsCertificate"]["extensions"]
        .as_array()
        .expect("extensions array");
    let eku_ext = extensions
        .iter()
        .find(|e| e["extnID"]["oid"] == "2.5.29.37")
        .expect("EKU extension should be present");
    let ekus = eku_ext["extnValue"]["extendedKeyUsage"]
        .as_array()
        .expect("extendedKeyUsage should be array");
    let oid_strings: Vec<&str> = ekus
        .iter()
        .filter_map(|e| e["oid"].as_str())
        .collect();
    assert!(
        oid_strings.contains(&"1.3.6.1.4.1.62558.2.1"),
        "EKU should contain c2pa-kp-claimSigning, got: {:?}",
        oid_strings
    );
}

#[test]
#[ignore]
fn ocsp_cert_has_ocsp_no_check() {
    let json = cert_profile::cert_to_json(&cert_path("test-ocsp.pem"))
        .expect("cert_to_json failed");
    let extensions = json["decoded"]["tbsCertificate"]["extensions"]
        .as_array()
        .expect("extensions array");
    let nc_ext = extensions
        .iter()
        .find(|e| e["extnID"]["oid"] == "1.3.6.1.5.5.7.48.1.5")
        .expect("OCSP No Check extension should be present");
    assert!(
        nc_ext["extnValue"]["ocspNoCheck"].is_null(),
        "ocspNoCheck should be null"
    );
}
