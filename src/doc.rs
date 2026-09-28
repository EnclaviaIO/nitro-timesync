//! Minimal decode of an NSM attestation document: just enough to read the
//! `timestamp` and tell a real Nitro NSM from QEMU's emulated one.
//!
//! The signature and certificate chain are deliberately NOT checked. The
//! document comes straight from this enclave's own /dev/nsm, which is
//! served by the Nitro hypervisor and not reachable by the parent
//! instance, so there is no party in the path to authenticate against.

use ciborium::Value;

use crate::decision::{EMULATED_RESOLUTION_MS, NITRO_RESOLUTION_MS};

/// COSE_Sign1 CBOR tag (RFC 9052). The NSM emits the untagged array, but
/// the tagged form is equally valid COSE and is accepted too.
const COSE_SIGN1_TAG: u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocTime {
    /// `timestamp` field: ms since the Unix epoch.
    pub timestamp_ms: u64,
    /// Granularity of `timestamp_ms`.
    pub resolution_ms: u64,
    /// Whether the document came from QEMU's emulated NSM.
    pub emulated: bool,
}

pub fn parse(document: &[u8]) -> Result<DocTime, String> {
    let envelope: Value =
        ciborium::from_reader(document).map_err(|e| format!("COSE envelope: {e}"))?;
    let envelope = match envelope {
        Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
        other => other,
    };
    let Value::Array(parts) = envelope else {
        return Err("COSE envelope is not an array".into());
    };
    if parts.len() != 4 {
        return Err(format!(
            "COSE envelope has {} parts, expected 4",
            parts.len()
        ));
    }
    let Value::Bytes(payload) = &parts[2] else {
        return Err("COSE payload is not a byte string".into());
    };

    let payload: Value =
        ciborium::from_reader(payload.as_slice()).map_err(|e| format!("payload: {e}"))?;
    let Value::Map(fields) = payload else {
        return Err("payload is not a map".into());
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
    };

    let timestamp_ms = match field("timestamp") {
        Some(Value::Integer(i)) => {
            u64::try_from(*i).map_err(|_| "timestamp is not a u64".to_string())?
        }
        Some(_) => return Err("timestamp is not an integer".into()),
        None => return Err("payload has no timestamp".into()),
    };

    // QEMU's virtio-nsm has no signing certificate and fills the field
    // with zero bytes; a real Nitro document carries a DER certificate.
    let emulated = match field("certificate") {
        Some(Value::Bytes(cert)) => cert.iter().all(|b| *b == 0),
        Some(_) => return Err("certificate is not a byte string".into()),
        None => return Err("payload has no certificate".into()),
    };

    Ok(DocTime {
        timestamp_ms,
        resolution_ms: if emulated {
            EMULATED_RESOLUTION_MS
        } else {
            NITRO_RESOLUTION_MS
        },
        emulated,
    })
}

/// Build a document shaped like the NSM's, for tests elsewhere in the crate.
#[cfg(test)]
pub fn encode_for_test(timestamp: Value, certificate: Option<Vec<u8>>, tagged: bool) -> Vec<u8> {
    let mut fields = vec![
        (
            Value::Text("module_id".into()),
            Value::Text("i-test-enc0".into()),
        ),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (Value::Text("timestamp".into()), timestamp),
    ];
    if let Some(cert) = certificate {
        fields.push((Value::Text("certificate".into()), Value::Bytes(cert)));
    }
    fields.push((Value::Text("nonce".into()), Value::Null));
    let mut payload = Vec::new();
    ciborium::into_writer(&Value::Map(fields), &mut payload).unwrap();
    let parts = Value::Array(vec![
        Value::Bytes(vec![0xa1, 0x01, 0x38, 0x22]),
        Value::Map(vec![]),
        Value::Bytes(payload),
        Value::Bytes(vec![0u8; 96]),
    ]);
    let envelope = if tagged {
        Value::Tag(COSE_SIGN1_TAG, Box::new(parts))
    } else {
        parts
    };
    let mut out = Vec::new();
    ciborium::into_writer(&envelope, &mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_cert() -> Option<Vec<u8>> {
        Some(vec![0x30, 0x82, 0x02, 0x7f, 0x01])
    }

    #[test]
    fn reads_timestamp_from_a_nitro_shaped_document() {
        let doc = encode_for_test(
            Value::Integer(1_800_000_000_123u64.into()),
            real_cert(),
            false,
        );
        assert_eq!(
            parse(&doc).unwrap(),
            DocTime {
                timestamp_ms: 1_800_000_000_123,
                resolution_ms: NITRO_RESOLUTION_MS,
                emulated: false
            }
        );
    }

    #[test]
    fn accepts_the_tagged_cose_form() {
        let doc = encode_for_test(
            Value::Integer(1_800_000_000_000u64.into()),
            real_cert(),
            true,
        );
        assert_eq!(parse(&doc).unwrap().timestamp_ms, 1_800_000_000_000);
    }

    #[test]
    fn zero_certificate_marks_the_emulated_nsm() {
        let doc = encode_for_test(
            Value::Integer(1_800_000_000_000u64.into()),
            Some(vec![0u8; 64]),
            false,
        );
        let t = parse(&doc).unwrap();
        assert!(t.emulated);
        assert_eq!(t.resolution_ms, EMULATED_RESOLUTION_MS);
    }

    #[test]
    fn rejects_malformed_documents() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0xff, 0x00]).is_err());
        // Negative timestamp.
        let doc = encode_for_test(Value::Integer((-1i64).into()), real_cert(), false);
        assert!(parse(&doc).is_err());
        // Timestamp of the wrong type.
        let doc = encode_for_test(Value::Text("now".into()), real_cert(), false);
        assert!(parse(&doc).is_err());
        // No certificate.
        let doc = encode_for_test(Value::Integer(1u64.into()), None, false);
        assert!(parse(&doc).is_err());
        // Envelope that is not a 4-element array.
        let mut short = Vec::new();
        ciborium::into_writer(&Value::Array(vec![Value::Null]), &mut short).unwrap();
        assert!(parse(&short).is_err());
    }

    #[test]
    fn missing_timestamp_is_an_error() {
        let mut payload = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![(
                Value::Text("certificate".into()),
                Value::Bytes(vec![1]),
            )]),
            &mut payload,
        )
        .unwrap();
        let mut doc = Vec::new();
        ciborium::into_writer(
            &Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Bytes(payload),
                Value::Bytes(vec![]),
            ]),
            &mut doc,
        )
        .unwrap();
        assert_eq!(parse(&doc), Err("payload has no timestamp".into()));
    }
}
