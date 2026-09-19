//! Stripe-style webhook signatures: `Stripe-Signature: t=<unix>,v1=<hex>`.
//!
//! Two things differ from the GitHub scheme and both are routinely got
//! wrong by hand-rolled verifiers:
//!
//! 1. The HMAC is **not** over the body. It is over
//!    `"{timestamp}.{raw_body}"` — the same `t` that is in the header,
//!    concatenated with a literal `.` in front of the body. An
//!    implementation that signs only the body produces a digest that
//!    looks plausible and never matches.
//! 2. A correct `v1` is not sufficient. The timestamp must also be
//!    recent, or an attacker who captured one genuine request can replay
//!    it forever — the signature stays valid because the signed bytes
//!    never change. The tolerance window is the only thing that stops it.

use crate::mac::{constant_time_eq, from_hex, hmac_sha256, to_hex};
use crate::verdict::Verdict;

pub const HEADER: &str = "Stripe-Signature";
/// Stripe's own libraries default to a five-minute window.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// A parsed `Stripe-Signature` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StripeSignature {
    pub timestamp: i64,
    /// Every `v1=` digest in the header. There can legitimately be more
    /// than one while a signing secret is being rotated, and the event is
    /// authentic if *any* of them matches.
    pub v1: Vec<Vec<u8>>,
}

/// The exact byte string Stripe signs: `"{timestamp}.{payload}"`.
pub fn signed_payload(timestamp: i64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 20);
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.push(b'.');
    out.extend_from_slice(body);
    out
}

/// The header value Stripe would send for this body, secret and `t`.
pub fn sign(secret: &[u8], body: &[u8], timestamp: i64) -> String {
    let digest = hmac_sha256(secret, &signed_payload(timestamp, body));
    format!("t={timestamp},v1={}", to_hex(&digest))
}

pub fn parse(header_value: &str) -> Result<StripeSignature, String> {
    let mut timestamp: Option<i64> = None;
    let mut v1: Vec<Vec<u8>> = Vec::new();

    for element in header_value.trim().split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        let Some((key, value)) = element.split_once('=') else {
            return Err(format!("`{element}` is not a `key=value` element"));
        };
        match key.trim() {
            "t" => {
                let parsed = value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| format!("`t={}` is not a unix timestamp", value.trim()))?;
                timestamp = Some(parsed);
            }
            "v1" => {
                let bytes = from_hex(value.trim())
                    .ok_or_else(|| format!("`v1={}` is not valid hex", value.trim()))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "a v1 signature is {} bytes, an HMAC-SHA256 digest is 32",
                        bytes.len()
                    ));
                }
                v1.push(bytes);
            }
            // `v0` is Stripe's test-mode-only scheme and other schemes may
            // be added later; ignoring unknown ones is what Stripe's own
            // libraries do, and is required for forward compatibility.
            _ => {}
        }
    }

    let Some(timestamp) = timestamp else {
        return Err(format!("no `t=` element in the {HEADER} header"));
    };
    if v1.is_empty() {
        return Err(format!(
            "no `v1=` element in the {HEADER} header (v0 is test-mode only and is not verified)"
        ));
    }
    Ok(StripeSignature { timestamp, v1 })
}

/// Verifies a `Stripe-Signature` header against the raw body, at time
/// `now` (unix seconds) with a `tolerance_secs` replay window.
///
/// The signature is checked first so the verdicts stay meaningful: a
/// stale-but-correctly-signed event reports `StaleTimestamp` (a replay),
/// while a stale event with a bad digest reports `Mismatch` — the more
/// serious of the two.
pub fn verify(
    secret: &[u8],
    body: &[u8],
    header_value: &str,
    now: i64,
    tolerance_secs: u64,
) -> Verdict {
    let parsed = match parse(header_value) {
        Ok(parsed) => parsed,
        Err(why) => return Verdict::Malformed(why),
    };

    let expected = hmac_sha256(secret, &signed_payload(parsed.timestamp, body));
    let matched = parsed
        .v1
        .iter()
        // `fold`, not `any`: `any` short-circuits, and during a secret
        // rotation that would make the time taken depend on which of the
        // supplied digests matched. Every candidate is compared.
        .fold(false, |acc, candidate| {
            constant_time_eq(&expected, candidate) | acc
        });

    if !matched {
        return Verdict::Mismatch;
    }

    let age_secs = now - parsed.timestamp;
    if age_secs.unsigned_abs() > tolerance_secs {
        return Verdict::StaleTimestamp {
            age_secs,
            tolerance_secs,
        };
    }
    Verdict::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    // A vector built exactly the way Stripe documents the construction:
    // signed_payload = t + "." + body. Independently reproducible:
    //
    //   $ printf '1719849600.{"id":"evt_test_webhook","object":"event"}' \
    //       | openssl dgst -sha256 -hmac 'whsec_test_secret'
    //   SHA2-256(stdin)= 88ce695ef1c916d5ef010b385ff02b2a5cdd948a249e3a6459aac03f4154244d
    const BODY: &[u8] = br#"{"id":"evt_test_webhook","object":"event"}"#;
    const SECRET: &[u8] = b"whsec_test_secret";
    const T: i64 = 1_719_849_600;
    const EXPECTED_HEX: &str = "88ce695ef1c916d5ef010b385ff02b2a5cdd948a249e3a6459aac03f4154244d";

    fn header() -> String {
        format!("t={T},v1={EXPECTED_HEX}")
    }

    #[test]
    fn signed_payload_is_timestamp_dot_body() {
        assert_eq!(
            signed_payload(T, BODY),
            format!("{T}.{}", std::str::from_utf8(BODY).unwrap()).into_bytes()
        );
    }

    #[test]
    fn matches_an_independently_computed_openssl_digest() {
        assert_eq!(sign(SECRET, BODY, T), header());
        assert_eq!(
            verify(SECRET, BODY, &header(), T + 10, DEFAULT_TOLERANCE_SECS),
            Verdict::Valid
        );
    }

    /// The bug this tool exists to prevent: a signature that is
    /// cryptographically perfect but was issued ten minutes ago. A
    /// verifier that only checks the HMAC calls this valid and happily
    /// re-processes a replayed payment event.
    #[test]
    fn a_correct_signature_outside_the_tolerance_window_is_rejected() {
        let verdict = verify(SECRET, BODY, &header(), T + 600, 300);
        assert_eq!(
            verdict,
            Verdict::StaleTimestamp {
                age_secs: 600,
                tolerance_secs: 300
            }
        );
        assert!(!verdict.is_valid());
        // ...and it really is the window doing the rejecting, not a bad
        // digest: the same header at the same "now" passes once the
        // window is widened past its age.
        assert_eq!(
            verify(SECRET, BODY, &header(), T + 600, 900),
            Verdict::Valid
        );
    }

    #[test]
    fn the_tolerance_boundary_is_inclusive_on_the_window_edge() {
        assert_eq!(
            verify(SECRET, BODY, &header(), T + 300, 300),
            Verdict::Valid
        );
        assert!(matches!(
            verify(SECRET, BODY, &header(), T + 301, 300),
            Verdict::StaleTimestamp { age_secs: 301, .. }
        ));
    }

    #[test]
    fn a_timestamp_far_in_the_future_is_rejected_too() {
        // Symmetric window: a forged far-future `t` would otherwise buy an
        // attacker an indefinitely valid signature.
        assert!(matches!(
            verify(SECRET, BODY, &header(), T - 3600, 300),
            Verdict::StaleTimestamp {
                age_secs: -3600,
                ..
            }
        ));
    }

    #[test]
    fn wrong_secret_is_rejected_even_inside_the_window() {
        assert_eq!(
            verify(b"whsec_wrong", BODY, &header(), T, 300),
            Verdict::Mismatch
        );
    }

    #[test]
    fn a_body_tampered_with_after_signing_is_rejected() {
        let tampered = br#"{"id":"evt_test_webhook","object":"EVENT"}"#;
        assert_eq!(
            verify(SECRET, tampered, &header(), T, 300),
            Verdict::Mismatch
        );
    }

    #[test]
    fn a_replayed_t_with_the_original_signature_does_not_validate() {
        // Attacker keeps the captured v1 but rewrites `t` to "now" to get
        // past the tolerance window. The digest covers `t`, so it breaks.
        let forged = format!("t={},v1={EXPECTED_HEX}", T + 600);
        assert_eq!(
            verify(SECRET, BODY, &forged, T + 600, 300),
            Verdict::Mismatch
        );
    }

    /// The single most common hand-rolled Stripe bug: signing the body
    /// alone and forgetting the `"{t}."` prefix. Such a signature must
    /// not verify.
    #[test]
    fn a_signature_over_the_body_alone_is_rejected() {
        let body_only = to_hex(&hmac_sha256(SECRET, BODY));
        assert_ne!(body_only, EXPECTED_HEX);
        assert_eq!(
            verify(SECRET, BODY, &format!("t={T},v1={body_only}"), T, 300),
            Verdict::Mismatch
        );
    }

    #[test]
    fn multiple_v1_signatures_pass_if_any_one_matches() {
        let decoy = "0".repeat(64);
        let rotating = format!("t={T},v1={decoy},v1={EXPECTED_HEX}");
        assert_eq!(verify(SECRET, BODY, &rotating, T, 300), Verdict::Valid);
        // Order must not matter.
        let rotating = format!("t={T},v1={EXPECTED_HEX},v1={decoy}");
        assert_eq!(verify(SECRET, BODY, &rotating, T, 300), Verdict::Valid);
        // And two wrong ones are still wrong.
        let none_match = format!("t={T},v1={decoy},v1={}", "1".repeat(64));
        assert_eq!(verify(SECRET, BODY, &none_match, T, 300), Verdict::Mismatch);
    }

    #[test]
    fn a_v0_only_header_is_not_silently_accepted() {
        // v0 is Stripe's test-mode scheme; treating it as verified would
        // be a false pass.
        let v0_only = format!("t={T},v0={EXPECTED_HEX}");
        assert!(matches!(
            verify(SECRET, BODY, &v0_only, T, 300),
            Verdict::Malformed(_)
        ));
        // But a v0 alongside a real v1 is ignored, not fatal.
        let both = format!("t={T},v0=deadbeef,v1={EXPECTED_HEX}");
        assert_eq!(verify(SECRET, BODY, &both, T, 300), Verdict::Valid);
    }

    #[test]
    fn whitespace_between_elements_is_tolerated() {
        assert_eq!(
            verify(
                SECRET,
                BODY,
                &format!(" t={T} , v1={EXPECTED_HEX} "),
                T,
                300
            ),
            Verdict::Valid
        );
    }

    #[test]
    fn malformed_headers_are_malformed_not_mismatches() {
        for bad in [
            EXPECTED_HEX.to_string(),                    // bare hex, no elements
            format!("v1={EXPECTED_HEX}"),                // no t
            format!("t={T}"),                            // no v1
            format!("t=not-a-number,v1={EXPECTED_HEX}"), // unparseable t
            format!("t={T},v1=zzzz"),                    // non-hex digest
            format!("t={T},v1=88ce695e"),                // truncated digest
            String::new(),                               // header missing
        ] {
            assert!(
                matches!(verify(SECRET, BODY, &bad, T, 300), Verdict::Malformed(_)),
                "expected Malformed for {bad:?}"
            );
        }
    }
}
