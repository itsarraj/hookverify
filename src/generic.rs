//! Generic HMAC-SHA256 mode: an arbitrary header, an arbitrary prefix,
//! hex or base64. This is the escape hatch for every in-house or
//! smaller-vendor webhook that does the same thing as GitHub's scheme
//! with its own spelling — Shopify's base64 `X-Shopify-Hmac-Sha256`, a
//! `X-Signature: v1=<hex>`, a bare hex digest with no prefix at all.

use crate::mac::{constant_time_eq, hmac_sha256, Encoding};
use crate::verdict::Verdict;

/// How to read a signature out of some vendor's header value.
#[derive(Clone, Debug)]
pub struct Scheme {
    /// Header name. Purely informational — it is echoed in the CLI output
    /// so the run is self-documenting — but it is what tells a reader
    /// which header the digest came out of.
    pub header: String,
    /// Literal prefix to strip before decoding, e.g. `sha256=` or `v1=`.
    /// Empty means the value is the bare digest.
    pub prefix: String,
    pub encoding: Encoding,
}

impl Default for Scheme {
    fn default() -> Self {
        Scheme {
            header: "X-Signature".to_string(),
            prefix: String::new(),
            encoding: Encoding::Hex,
        }
    }
}

impl Scheme {
    /// The header value this scheme would produce for a given body.
    pub fn sign(&self, secret: &[u8], body: &[u8]) -> String {
        format!(
            "{}{}",
            self.prefix,
            self.encoding.encode(&hmac_sha256(secret, body))
        )
    }

    pub fn verify(&self, secret: &[u8], body: &[u8], header_value: &str) -> Verdict {
        let value = header_value.trim();
        let digest_text = match value.strip_prefix(self.prefix.as_str()) {
            Some(rest) => rest,
            None => {
                return Verdict::Malformed(format!(
                    "expected the value to start with `{}`, got `{value}`",
                    self.prefix
                ))
            }
        };

        let Some(provided) = self.encoding.decode(digest_text) else {
            return Verdict::Malformed(format!(
                "`{digest_text}` is not valid {}",
                self.encoding.name()
            ));
        };
        if provided.len() != 32 {
            return Verdict::Malformed(format!(
                "signature decodes to {} bytes, an HMAC-SHA256 digest is 32 — wrong encoding?",
                provided.len()
            ));
        }

        let expected = hmac_sha256(secret, body);
        if constant_time_eq(&expected, &provided) {
            Verdict::Valid
        } else {
            Verdict::Mismatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independently reproducible, both encodings of the same digest:
    //
    //   $ printf '{"order_id":1234}' | openssl dgst -sha256 -hmac 'shpss_generic_secret'
    //   SHA2-256(stdin)= aa10016d8ec8fe224a024c4a52c27e2edac4aa22a502d81a209172bdbf1487fb
    //   $ printf '{"order_id":1234}' | openssl dgst -sha256 -hmac 'shpss_generic_secret' -binary | base64
    //   qhABbY7I/iJKAkxKUsJ+LtrEqiKlAtgaIJFyvb8Uh/s=
    const BODY: &[u8] = br#"{"order_id":1234}"#;
    const SECRET: &[u8] = b"shpss_generic_secret";
    const HEX: &str = "aa10016d8ec8fe224a024c4a52c27e2edac4aa22a502d81a209172bdbf1487fb";
    const B64: &str = "qhABbY7I/iJKAkxKUsJ+LtrEqiKlAtgaIJFyvb8Uh/s=";

    fn hex_scheme() -> Scheme {
        Scheme::default()
    }

    fn b64_scheme() -> Scheme {
        Scheme {
            header: "X-Shopify-Hmac-Sha256".to_string(),
            prefix: String::new(),
            encoding: Encoding::Base64,
        }
    }

    #[test]
    fn bare_hex_matches_the_openssl_digest() {
        assert_eq!(hex_scheme().sign(SECRET, BODY), HEX);
        assert_eq!(hex_scheme().verify(SECRET, BODY, HEX), Verdict::Valid);
    }

    #[test]
    fn base64_matches_the_same_digest_openssl_base64_encoded() {
        assert_eq!(b64_scheme().sign(SECRET, BODY), B64);
        assert_eq!(b64_scheme().verify(SECRET, BODY, B64), Verdict::Valid);
    }

    #[test]
    fn a_custom_prefix_is_stripped_before_decoding() {
        let scheme = Scheme {
            header: "X-Signature".to_string(),
            prefix: "v1=".to_string(),
            encoding: Encoding::Hex,
        };
        assert_eq!(scheme.sign(SECRET, BODY), format!("v1={HEX}"));
        assert_eq!(
            scheme.verify(SECRET, BODY, &format!("v1={HEX}")),
            Verdict::Valid
        );
        // Value without the configured prefix: a config mistake, reported
        // as such rather than as a failed signature.
        assert!(matches!(
            scheme.verify(SECRET, BODY, HEX),
            Verdict::Malformed(_)
        ));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        assert_eq!(
            hex_scheme().verify(b"not-the-secret", BODY, HEX),
            Verdict::Mismatch
        );
        assert_eq!(
            b64_scheme().verify(b"not-the-secret", BODY, B64),
            Verdict::Mismatch
        );
    }

    #[test]
    fn a_body_tampered_with_after_signing_is_rejected() {
        assert_eq!(
            hex_scheme().verify(SECRET, br#"{"order_id":1235}"#, HEX),
            Verdict::Mismatch
        );
    }

    #[test]
    fn the_wrong_encoding_is_a_malformed_report_not_a_mismatch() {
        // Handing a base64 digest to hex mode decodes to the wrong length
        // (or not at all) — telling someone "invalid signature" here would
        // send them hunting for a secret mismatch that does not exist.
        assert!(matches!(
            hex_scheme().verify(SECRET, BODY, B64),
            Verdict::Malformed(_)
        ));
        assert!(matches!(
            b64_scheme().verify(SECRET, BODY, HEX),
            Verdict::Malformed(_)
        ));
    }

    #[test]
    fn a_truncated_digest_is_malformed() {
        assert!(matches!(
            hex_scheme().verify(SECRET, BODY, &HEX[..32]),
            Verdict::Malformed(_)
        ));
        assert!(matches!(
            hex_scheme().verify(SECRET, BODY, ""),
            Verdict::Malformed(_)
        ));
    }
}
