// Copyright 2026 Encypher AI. Licensed under the Apache License, Version 2.0.
//
// Certificate profile validation for C2PA conformance program.
//
// Parses PEM/DER X.509 certificates and serializes them to the JSON format
// expected by the C2PA certificate profile JSON schemas (rootCA,
// claimSigningIssuingCA, claimSigningLeaf.al1, ocspResponderLeaf).  The JSON
// output is then validated against the schema using the `jsonschema` crate.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use der_parser::der::{parse_der, parse_der_sequence};
use serde_json::{json, Value};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::*,
};

// ---------------------------------------------------------------------------
// OID constants (dotted-string form)
// ---------------------------------------------------------------------------

const OID_CN: &str = "2.5.4.3";
const OID_COUNTRY: &str = "2.5.4.6";
const OID_ORG: &str = "2.5.4.10";
const OID_OU: &str = "2.5.4.11";
const OID_STATE: &str = "2.5.4.8";
const OID_LOCALITY: &str = "2.5.4.7";
const OID_SERIAL_NUMBER: &str = "2.5.4.5";
const OID_EMAIL: &str = "1.2.840.113549.1.9.1";

const OID_SKI: &str = "2.5.29.14";
const OID_AKI: &str = "2.5.29.35";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_EKU: &str = "2.5.29.37";
const OID_CERT_POLICIES: &str = "2.5.29.32";
const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";
const OID_CRL_DP: &str = "2.5.29.31";
const OID_SAN: &str = "2.5.29.17";
const OID_OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";

const OID_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
const OID_CPS_QUALIFIER: &str = "1.3.6.1.5.5.7.2.1";
const OID_UNOTICE_QUALIFIER: &str = "1.3.6.1.5.5.7.2.2";

// Signature algorithms
const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const OID_ED25519: &str = "1.3.101.112";

// Key algorithms
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

// EC curves
const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
const OID_SECP384R1: &str = "1.3.132.0.34";
const OID_SECP521R1: &str = "1.3.132.0.35";

// EKU OIDs
const OID_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const OID_DOC_SIGNING_ADOBE: &str = "1.2.840.113583.1.1.5";
const OID_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
const OID_C2PA_CLAIM_SIGNING: &str = "1.3.6.1.4.1.62558.2.1";

// C2PA private extensions
const OID_C2PA_CP: &str = "1.3.6.1.4.1.62558.1.1";
const OID_C2PA_ASSURANCE_LEVEL: &str = "1.3.6.1.4.1.62558.3";
const OID_C2PA_CPL_RECORD: &str = "1.3.6.1.4.1.62558.4";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Reads a PEM or DER certificate file and returns the JSON representation
/// matching the C2PA certificate profile schema format.
pub fn cert_to_json(path: &Path) -> Result<Value> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let der_bytes = if looks_like_pem(&data) {
        let p = ::pem::parse(&data).with_context(|| "failed to parse PEM")?;
        p.into_contents()
    } else {
        data
    };
    let (_, cert) = X509Certificate::from_der(&der_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;
    Ok(serialize_cert(&cert, &der_bytes))
}

/// Validates a certificate JSON value against a JSON schema.
pub fn validate_cert_json(cert_json: &Value, schema_json: &Value) -> Result<Vec<String>> {
    let validator = jsonschema::validator_for(schema_json)
        .map_err(|e| anyhow::anyhow!("invalid JSON schema: {e}"))?;
    let result = validator.validate(cert_json);
    let errors: Vec<String> = match result {
        Ok(()) => Vec::new(),
        Err(error_iter) => error_iter
            .map(|e| {
                let path = e.instance_path.to_string();
                if path.is_empty() {
                    format!("{e}")
                } else {
                    format!("{path}: {e}")
                }
            })
            .collect(),
    };
    // errors must be fully collected before validator is dropped.
    Ok(errors)
}

/// Loads a JSON schema from a file.
pub fn load_schema(path: &Path) -> Result<Value> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("failed to parse {}", path.display()))
}

/// Result of a single certificate profile validation.
#[derive(Debug)]
pub struct CertProfileResult {
    pub cert_path: String,
    pub schema_path: String,
    pub cert_json: Value,
    pub errors: Vec<String>,
    pub passed: bool,
}

/// Validates a certificate file against a schema file.
pub fn validate_cert_profile(cert_path: &Path, schema_path: &Path) -> Result<CertProfileResult> {
    let cert_json = cert_to_json(cert_path)?;
    let schema_json = load_schema(schema_path)?;
    let errors = validate_cert_json(&cert_json, &schema_json)?;
    let passed = errors.is_empty();
    Ok(CertProfileResult {
        cert_path: cert_path.display().to_string(),
        schema_path: schema_path.display().to_string(),
        cert_json,
        errors,
        passed,
    })
}

// ---------------------------------------------------------------------------
// JSON serialization
// ---------------------------------------------------------------------------

fn serialize_cert(cert: &X509Certificate<'_>, raw_der: &[u8]) -> Value {
    json!({
        "format": "certificate",
        "decoded": serialize_decoded(cert),
        "raw_hex": hex::encode(raw_der),
    })
}

fn serialize_decoded(cert: &X509Certificate<'_>) -> Value {
    let sig_alg_oid = cert.signature_algorithm.algorithm.to_id_string();
    json!({
        "tbsCertificate": serialize_tbs(cert),
        "signatureAlgorithm": serialize_algorithm_id(&sig_alg_oid),
        "signatureValue_hex": hex::encode(cert.signature_value.data.as_ref()),
    })
}

fn serialize_tbs(cert: &X509Certificate<'_>) -> Value {
    let tbs = &cert.tbs_certificate;
    let sig_oid = tbs.signature.algorithm.to_id_string();
    let serial_hex = format!("0x{}", hex::encode(tbs.raw_serial()));

    let mut obj = json!({
        "version": {
            "value": tbs.version.0,
            "rawValue": format!("v{}", tbs.version.0 + 1),
        },
        "serialNumber_hex": serial_hex,
        "signature": serialize_algorithm_id(&sig_oid),
        "issuer": serialize_name(&tbs.issuer),
        "validity": serialize_validity(cert),
        "subject": serialize_name(&tbs.subject),
        "subjectPublicKeyInfo": serialize_spki(cert),
    });

    let extensions = serialize_extensions(cert);
    if !extensions.is_empty() {
        obj["extensions"] = Value::Array(extensions);
    }

    obj
}

fn serialize_algorithm_id(oid: &str) -> Value {
    json!({
        "algorithm": {
            "oid": oid,
            "name": algorithm_name(oid),
        }
    })
}

fn algorithm_name(oid: &str) -> String {
    match oid {
        OID_SHA256_RSA => "sha256WithRSAEncryption".into(),
        OID_SHA384_RSA => "sha384WithRSAEncryption".into(),
        OID_SHA512_RSA => "sha512WithRSAEncryption".into(),
        OID_RSASSA_PSS => "rsassaPss".into(),
        OID_ECDSA_SHA256 => "ecdsa-with-SHA256".into(),
        OID_ECDSA_SHA384 => "ecdsa-with-SHA384".into(),
        OID_ECDSA_SHA512 => "ecdsa-with-SHA512".into(),
        OID_ED25519 => "Ed25519".into(),
        OID_EC_PUBLIC_KEY => "id-ecPublicKey".into(),
        OID_RSA_ENCRYPTION => "rsaEncryption".into(),
        _ => format!("OID:{oid}"),
    }
}

fn oid_name(oid: &str) -> String {
    match oid {
        OID_CN => "commonName".into(),
        OID_COUNTRY => "countryName".into(),
        OID_ORG => "organizationName".into(),
        OID_OU => "organizationalUnitName".into(),
        OID_STATE => "stateOrProvinceName".into(),
        OID_LOCALITY => "localityName".into(),
        OID_SERIAL_NUMBER => "serialNumber".into(),
        OID_EMAIL => "emailAddress".into(),
        OID_SKI => "subjectKeyIdentifier".into(),
        OID_AKI => "authorityKeyIdentifier".into(),
        OID_KEY_USAGE => "keyUsage".into(),
        OID_BASIC_CONSTRAINTS => "basicConstraints".into(),
        OID_EKU => "extKeyUsage".into(),
        OID_CERT_POLICIES => "certificatePolicies".into(),
        OID_AIA => "authorityInfoAccess".into(),
        OID_CRL_DP => "cRLDistributionPoints".into(),
        OID_SAN => "subjectAltName".into(),
        OID_OCSP_NO_CHECK => "id-pkix-ocsp-nocheck".into(),
        OID_OCSP => "id-ad-ocsp".into(),
        OID_CA_ISSUERS => "id-ad-caIssuers".into(),
        OID_CPS_QUALIFIER => "id-qt-cps".into(),
        OID_UNOTICE_QUALIFIER => "id-qt-unotice".into(),
        OID_EMAIL_PROTECTION => "id-kp-emailProtection".into(),
        OID_DOC_SIGNING_ADOBE => "id-kp-documentSigning".into(),
        OID_OCSP_SIGNING => "id-kp-OCSPSigning".into(),
        OID_C2PA_CLAIM_SIGNING => "c2pa-kp-claimSigning".into(),
        OID_C2PA_CP => "c2pa-certificate-policy".into(),
        OID_C2PA_ASSURANCE_LEVEL => "c2pa-assurance-level".into(),
        OID_C2PA_CPL_RECORD => "c2pa-cpl-record".into(),
        _ => format!("OID:{oid}"),
    }
}

// ---------------------------------------------------------------------------
// Name (RDNSequence)
// ---------------------------------------------------------------------------

fn serialize_name(name: &X509Name<'_>) -> Value {
    let rdns: Vec<Value> = name
        .iter()
        .map(|rdn| {
            let atvs: Vec<Value> = rdn
                .iter()
                .map(|atv| {
                    let oid_str = atv.attr_type().to_id_string();
                    let value = atv
                        .as_str()
                        .map(|s| Value::String(s.to_string()))
                        .unwrap_or_else(|_| {
                            Value::String(format!("(hex){}", hex::encode(atv.as_slice())))
                        });
                    json!({
                        "type": { "oid": oid_str, "name": oid_name(&oid_str) },
                        "value": value,
                    })
                })
                .collect();
            Value::Array(atvs)
        })
        .collect();
    Value::Array(rdns)
}

// ---------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------

fn serialize_validity(cert: &X509Certificate<'_>) -> Value {
    let tbs = &cert.tbs_certificate;
    let not_before = tbs.validity.not_before;
    let not_after = tbs.validity.not_after;

    let encode_time = |t: ASN1Time| -> Value {
        let dt = t.to_datetime();
        let encoding = if dt.year() < 2050 {
            "UTCTime"
        } else {
            "GeneralizedTime"
        };
        // Manual ISO 8601 / RFC 3339 format (time crate formatting feature
        // is not enabled in the dependency tree).
        let formatted = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        );
        json!({ "_encoding": encoding, "value": formatted })
    };

    let days = {
        let dur = not_after.to_datetime() - not_before.to_datetime();
        dur.whole_days()
    };

    json!({
        "notBefore": encode_time(not_before),
        "notAfter": encode_time(not_after),
        "computedValidityDays": days,
    })
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo
// ---------------------------------------------------------------------------

fn serialize_spki(cert: &X509Certificate<'_>) -> Value {
    let spki = &cert.tbs_certificate.subject_pki;
    let algo_oid = spki.algorithm.algorithm.to_id_string();
    let raw_spki_hex = hex::encode(spki.raw);

    let mut pk = json!({
        "spki_algorithm": serialize_algorithm_id(&algo_oid),
        "raw_spki_hex": raw_spki_hex,
    });

    if algo_oid == OID_EC_PUBLIC_KEY {
        if let Some(params) = &spki.algorithm.parameters {
            if let Ok(oid) = params.as_oid() {
                let curve_oid = oid.to_id_string();
                let (curve_name, bits) = match curve_oid.as_str() {
                    OID_SECP256R1 => ("secp256r1", 256),
                    OID_SECP384R1 => ("secp384r1", 384),
                    OID_SECP521R1 => ("secp521r1", 521),
                    _ => ("unknown", 0),
                };
                pk["curve"] = json!(curve_name);
                pk["key_size_bits"] = json!(bits);
            }
        }
        pk["point_uncompressed_hex"] = json!(hex::encode(&*spki.subject_public_key.data));
    } else if algo_oid == OID_RSA_ENCRYPTION {
        if let Ok((_, seq_obj)) = parse_der_sequence(&spki.subject_public_key.data) {
            if let Ok(items) = seq_obj.as_sequence() {
                if items.len() >= 2 {
                    if let Ok(n) = items[0].as_biguint() {
                        let bits = n.bits();
                        pk["modulus_bits"] = json!(bits);
                        pk["modulus_hex"] = json!(format!("0x{}", n.to_str_radix(16)));
                    }
                    if let Ok(e) = items[1].as_u64() {
                        pk["publicExponent"] = json!(e);
                    }
                }
            }
        }
    } else if algo_oid == OID_ED25519 {
        pk["curve"] = json!("Ed25519");
        pk["key_size_bits"] = json!(256);
    }

    json!({ "publicKey": pk })
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

fn serialize_extensions(cert: &X509Certificate<'_>) -> Vec<Value> {
    cert.tbs_certificate
        .extensions()
        .iter()
        .map(|ext| serialize_extension(ext))
        .collect()
}

fn serialize_extension(ext: &X509Extension<'_>) -> Value {
    let oid_str = ext.oid.to_id_string();
    let mut extn_value = json!({ "_raw_value_hex": hex::encode(ext.value) });

    match ext.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(ski) => {
            extn_value["keyIdentifier_hex"] = json!(hex::encode(ski.0));
        }
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            if let Some(kid) = &aki.key_identifier {
                extn_value["keyIdentifier_hex"] = json!(hex::encode(kid.0));
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            extn_value["digitalSignature"] = json!(ku.digital_signature());
            extn_value["contentCommitment"] = json!(ku.non_repudiation());
            extn_value["keyEncipherment"] = json!(ku.key_encipherment());
            extn_value["dataEncipherment"] = json!(ku.data_encipherment());
            extn_value["keyAgreement"] = json!(ku.key_agreement());
            extn_value["keyCertSign"] = json!(ku.key_cert_sign());
            extn_value["cRLSign"] = json!(ku.crl_sign());
            extn_value["encipherOnly"] = json!(ku.encipher_only());
            extn_value["decipherOnly"] = json!(ku.decipher_only());
        }
        ParsedExtension::BasicConstraints(bc) => {
            extn_value["cA"] = json!(bc.ca);
            extn_value["pathLenConstraint"] = match bc.path_len_constraint {
                Some(pl) => json!(pl),
                None => Value::Null,
            };
        }
        ParsedExtension::ExtendedKeyUsage(_) => {
            // Re-parse from DER to get all OIDs including custom ones.
            let oid_strings = parse_eku_oids_from_der(ext.value);
            let oids: Vec<Value> = oid_strings
                .iter()
                .map(|s| json!({ "oid": s, "name": oid_name(s) }))
                .collect();
            extn_value["extendedKeyUsage"] = Value::Array(oids);
        }
        ParsedExtension::CertificatePolicies(policies) => {
            let items: Vec<Value> = policies
                .iter()
                .map(serialize_policy_information)
                .collect();
            extn_value["certificatePolicies"] = Value::Array(items);
        }
        ParsedExtension::AuthorityInfoAccess(aia) => {
            let items: Vec<Value> = aia
                .accessdescs
                .iter()
                .map(serialize_access_description)
                .collect();
            extn_value["authorityInfoAccess"] = Value::Array(items);
        }
        ParsedExtension::CRLDistributionPoints(cdp) => {
            let items: Vec<Value> = cdp
                .iter()
                .map(serialize_crl_distribution_point)
                .collect();
            extn_value["cRLDistributionPoints"] = Value::Array(items);
        }
        _ => {
            // Handle known extensions that x509-parser does not parse.
            if oid_str == OID_OCSP_NO_CHECK {
                // OCSP No Check (RFC 6960): value is ASN.1 NULL.
                extn_value["ocspNoCheck"] = Value::Null;
            } else {
                // C2PA assurance level, CPL record, etc.
                decode_unknown_extension(ext.value, &mut extn_value);
            }
        }
    }

    json!({
        "extnID": { "oid": oid_str, "name": oid_name(&oid_str) },
        "critical": ext.critical,
        "extnValue": extn_value,
    })
}

// ---------------------------------------------------------------------------
// EKU OID extraction from DER
// ---------------------------------------------------------------------------

fn parse_eku_oids_from_der(ext_value: &[u8]) -> Vec<String> {
    if let Ok((_, seq_obj)) = parse_der_sequence(ext_value) {
        if let Ok(items) = seq_obj.as_sequence() {
            return items
                .iter()
                .filter_map(|obj| obj.as_oid().ok().map(|oid| oid.to_id_string()))
                .collect();
        }
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Certificate Policies
// ---------------------------------------------------------------------------

fn serialize_policy_information(
    pi: &x509_parser::extensions::PolicyInformation<'_>,
) -> Value {
    let oid_str = pi.policy_id.to_id_string();
    let mut obj = json!({
        "policyIdentifier": { "oid": oid_str, "name": oid_name(&oid_str) },
    });

    if let Some(qualifiers) = &pi.policy_qualifiers {
        let quals: Vec<Value> = qualifiers
            .iter()
            .map(|q| {
                let q_oid = q.policy_qualifier_id.to_id_string();
                let type_name = match q_oid.as_str() {
                    OID_CPS_QUALIFIER => "id-qt-cps",
                    OID_UNOTICE_QUALIFIER => "id-qt-unotice",
                    _ => "UNKNOWN",
                };
                let mut qv = json!({ "_type": type_name });
                if q_oid == OID_CPS_QUALIFIER {
                    // Qualifier is DER-encoded IA5String containing the CPS URI.
                    if let Ok((_, der_obj)) = parse_der(q.qualifier) {
                        if let Ok(s) = der_obj.as_str() {
                            qv["CPSuri"] = json!(s);
                        }
                    }
                }
                qv
            })
            .collect();
        obj["policyQualifiers"] = Value::Array(quals);
    }

    obj
}

// ---------------------------------------------------------------------------
// Authority Information Access
// ---------------------------------------------------------------------------

fn serialize_access_description(
    ad: &x509_parser::extensions::AccessDescription<'_>,
) -> Value {
    let method_oid = ad.access_method.to_id_string();
    json!({
        "accessMethod": { "oid": method_oid, "name": oid_name(&method_oid) },
        "accessLocation": serialize_general_name(&ad.access_location),
    })
}

// ---------------------------------------------------------------------------
// CRL Distribution Points
// ---------------------------------------------------------------------------

fn serialize_crl_distribution_point(
    dp: &x509_parser::extensions::CRLDistributionPoint<'_>,
) -> Value {
    let mut obj = json!({});
    if let Some(dpn) = &dp.distribution_point {
        match dpn {
            DistributionPointName::FullName(names) => {
                let full_name: Vec<Value> = names.iter().map(serialize_general_name).collect();
                obj["distributionPoint"] = json!({ "fullName": full_name });
            }
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                let atvs: Vec<Value> = rdn
                    .iter()
                    .map(|atv| {
                        let o = atv.attr_type().to_id_string();
                        let v = atv
                            .as_str()
                            .map(|s| Value::String(s.to_string()))
                            .unwrap_or_else(|_| {
                                Value::String(format!("(hex){}", hex::encode(atv.as_slice())))
                            });
                        json!({ "type": { "oid": o, "name": oid_name(&o) }, "value": v })
                    })
                    .collect();
                obj["distributionPoint"] = json!({ "nameRelativeToCRLIssuer": atvs });
            }
        }
    }
    obj
}

// ---------------------------------------------------------------------------
// GeneralName
// ---------------------------------------------------------------------------

fn serialize_general_name(gn: &GeneralName<'_>) -> Value {
    match gn {
        GeneralName::URI(uri) => {
            json!({ "_type": "uniformResourceIdentifier", "value": *uri })
        }
        GeneralName::RFC822Name(name) => {
            json!({ "_type": "rfc822Name", "value": *name })
        }
        GeneralName::DNSName(name) => {
            json!({ "_type": "dNSName", "value": *name })
        }
        GeneralName::DirectoryName(name) => {
            json!({ "_type": "directoryName", "value": serialize_name(name) })
        }
        GeneralName::IPAddress(bytes) => {
            json!({ "_type": "iPAddress", "value": hex::encode(bytes) })
        }
        GeneralName::RegisteredID(oid) => {
            json!({ "_type": "registeredID", "value": oid.to_id_string() })
        }
        _ => json!({ "_type": "UNKNOWN" }),
    }
}

// ---------------------------------------------------------------------------
// Unknown extension decoder (for _pyasn1_decoded)
// ---------------------------------------------------------------------------

fn decode_unknown_extension(value: &[u8], out: &mut Value) {
    match parse_der(value) {
        Ok((_, obj)) => {
            if let Ok(oid) = obj.as_oid() {
                out["_pyasn1_decoded"] = json!({
                    "_asn1_type": "ObjectIdentifier",
                    "value": oid.to_id_string(),
                });
            } else if let Ok(s) = obj.as_str() {
                // UTF8String, PrintableString, IA5String, etc.
                let asn1_type = match obj.tag().0 {
                    12 => "UTF8String",
                    19 => "PrintableString",
                    22 => "IA5String",
                    _ => "OctetString",
                };
                out["_pyasn1_decoded"] = json!({
                    "_asn1_type": asn1_type,
                    "value": s,
                });
            } else if let Ok(b) = obj.as_bool() {
                out["_pyasn1_decoded"] = json!({
                    "_asn1_type": "Boolean",
                    "value": b,
                });
            } else if obj.tag().0 == 5 {
                // NULL
                out["_pyasn1_decoded"] = json!({
                    "_asn1_type": "Null",
                    "value": null,
                });
            } else if let Ok(i) = obj.as_i64() {
                out["_pyasn1_decoded"] = json!({
                    "_asn1_type": "Integer",
                    "value": i,
                });
            } else {
                out["_unrecognized"] = json!(true);
                out["_generic_value_repr"] = json!(hex::encode(value));
            }
        }
        Err(_) => {
            out["_unrecognized"] = json!(true);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn looks_like_pem(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ")
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/// Formats the validation result as a structured JSON report.
pub fn format_result_json(result: &CertProfileResult) -> Value {
    json!({
        "cert_path": result.cert_path,
        "schema_path": result.schema_path,
        "passed": result.passed,
        "error_count": result.errors.len(),
        "errors": result.errors,
    })
}

/// Formats the validation result as human-readable text.
pub fn format_result_text(result: &CertProfileResult) -> String {
    let mut out = String::new();
    let status = if result.passed { "PASS" } else { "FAIL" };
    out.push_str(&format!(
        "[{}] {} vs {}\n",
        status, result.cert_path, result.schema_path
    ));
    if result.passed {
        out.push_str("  Certificate matches the C2PA profile schema.\n");
    } else {
        out.push_str(&format!("  {} error(s):\n", result.errors.len()));
        for (i, err) in result.errors.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", i + 1, err));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_pem_detects_header() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE-----\n"));
        assert!(!looks_like_pem(b"\x30\x82"));
    }

    #[test]
    fn algorithm_name_returns_known() {
        assert_eq!(algorithm_name(OID_ECDSA_SHA384), "ecdsa-with-SHA384");
        assert_eq!(algorithm_name("1.2.3.4"), "OID:1.2.3.4");
    }

    #[test]
    fn oid_name_returns_known() {
        assert_eq!(oid_name(OID_C2PA_CLAIM_SIGNING), "c2pa-kp-claimSigning");
        assert_eq!(oid_name(OID_C2PA_ASSURANCE_LEVEL), "c2pa-assurance-level");
    }
}
