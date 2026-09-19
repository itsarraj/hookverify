//! GitHub-style webhook signatures: `X-Hub-Signature-256: sha256=<hex>`,
//! an HMAC-SHA256 over the **raw** request body under the secret
//! configured on the webhook.

use crate::mac::{constant_time_eq, from_hex, hmac_sha256};
use crate::verdict::Verdict;

pub const HEADER: &str = "X-Hub-Signature-256";
pub const PREFIX: &str = "sha256=";

/// The header value GitHub would send for this body and secret.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    format!("{PREFIX}{}", crate::mac::to_hex(&hmac_sha256(secret, body)))
}

/// Verifies a `X-Hub-Signature-256` header value against the raw body.
///
/// The `sha256=` prefix is required rather than optional: GitHub always
/// sends it, so a value arriving without one means something upstream
/// mangled the header, and quietly accepting it would hide that.
pub fn verify(secret: &[u8], body: &[u8], header_value: &str) -> Verdict {
    let value = header_value.trim();

    let Some(hex) = value.strip_prefix(PREFIX) else {
        if value.starts_with("sha1=") {
            return Verdict::Malformed(format!(
                "got a sha1= signature; that is the deprecated X-Hub-Signature header, not {HEADER}"
            ));
        }
        return Verdict::Malformed(format!(
            "expected a value shaped like `{PREFIX}<64 hex chars>`, got `{value}`"
        ));
    };

    let Some(provided) = from_hex(hex) else {
        return Verdict::Malformed(format!("`{hex}` after `{PREFIX}` is not valid hex"));
    };
    if provided.len() != 32 {
        return Verdict::Malformed(format!(
            "signature is {} bytes, an HMAC-SHA256 digest is 32 (64 hex chars)",
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

#[cfg(test)]
mod tests {
    use super::*;

    // GitHub's own documented example: payload "Hello, World!" with the
    // secret "It's a Secret to Everybody". The expected digest below is
    // the one in GitHub's docs, and is reproducible outside this repo:
    //
    //   $ printf 'Hello, World!' | openssl dgst -sha256 -hmac "It's a Secret to Everybody"
    //   SHA2-256(stdin)= 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
    const BODY: &[u8] = b"Hello, World!";
    const SECRET: &[u8] = b"It's a Secret to Everybody";
    const EXPECTED_HEX: &str = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    #[test]
    fn matches_githubs_own_documented_example() {
        assert_eq!(sign(SECRET, BODY), format!("sha256={EXPECTED_HEX}"));
        assert_eq!(
            verify(SECRET, BODY, &format!("sha256={EXPECTED_HEX}")),
            Verdict::Valid
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        // openssl with the wrong secret gives a completely different
        // digest (067a9355...), i.e. there is nothing to "almost match".
        assert_eq!(
            verify(b"wrong-secret", BODY, &format!("sha256={EXPECTED_HEX}")),
            Verdict::Mismatch
        );
    }

    #[test]
    fn a_body_tampered_with_after_signing_is_rejected() {
        // Same secret, same signature, one byte of the body changed
        // ('!' -> '?'). This is the actual attack the header exists to
        // stop, and the digest for the tampered body is 319468fd... —
        // no relation to the original.
        assert_eq!(
            verify(SECRET, b"Hello, World?", &format!("sha256={EXPECTED_HEX}")),
            Verdict::Mismatch
        );
    }

    #[test]
    fn a_signature_differing_in_one_hex_char_is_rejected() {
        let mut tweaked = EXPECTED_HEX.to_string();
        tweaked.replace_range(0..1, "8"); // leading '7' -> '8'
        assert_eq!(
            verify(SECRET, BODY, &format!("sha256={tweaked}")),
            Verdict::Mismatch
        );
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        assert_eq!(
            verify(
                SECRET,
                BODY,
                &format!("sha256={}", EXPECTED_HEX.to_uppercase())
            ),
            Verdict::Valid
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            verify(SECRET, BODY, &format!("  sha256={EXPECTED_HEX}\n")),
            Verdict::Valid
        );
    }

    #[test]
    fn an_empty_body_still_verifies_rather_than_erroring() {
        // A zero-length body is legal and still has a well-defined HMAC;
        // it must not be treated as "nothing to check".
        let sig = sign(SECRET, b"");
        assert_eq!(verify(SECRET, b"", &sig), Verdict::Valid);
        assert_eq!(verify(SECRET, b"x", &sig), Verdict::Mismatch);
    }

    #[test]
    fn malformed_headers_are_malformed_not_mismatches() {
        // Each of these is a plumbing bug, not an attack, and saying
        // "invalid signature" for them sends people debugging the wrong
        // thing.
        for bad in [
            EXPECTED_HEX, // prefix stripped by a proxy
            "sha256=",    // empty digest
            "sha256=not-hex-at-all-not-hex-at-all-not-hex-at-all-not-hex-at-allxx",
            "sha256=757107ea", // truncated to 4 bytes
            "",                // header missing entirely
        ] {
            assert!(
                matches!(verify(SECRET, BODY, bad), Verdict::Malformed(_)),
                "expected Malformed for {bad:?}"
            );
        }
    }

    #[test]
    fn a_sha1_signature_is_called_out_by_name() {
        let Verdict::Malformed(why) = verify(
            SECRET,
            BODY,
            "sha1=0ae4e7a2d5e2b2a1c0b1a2c3d4e5f60718293a4b",
        ) else {
            panic!("expected Malformed");
        };
        assert!(
            why.contains("sha1"),
            "message should name the problem: {why}"
        );
    }
}
