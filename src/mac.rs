//! The crypto primitives every webhook-signature scheme in this tool is
//! built on: HMAC-SHA256, hex/base64 codecs for the digest, and — the
//! detail hand-rolled verifiers get wrong most often — a constant-time
//! comparison of the computed digest against the one the sender supplied.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How a digest is spelled in the header. Hex is what GitHub and Stripe
/// use; base64 is what a lot of "generic" senders (Shopify, Slack-ish
/// in-house schemes) use for the exact same HMAC-SHA256 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    Base64,
}

impl Encoding {
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Encoding::Hex => to_hex(bytes),
            Encoding::Base64 => to_base64(bytes),
        }
    }

    pub fn decode(self, text: &str) -> Option<Vec<u8>> {
        match self {
            Encoding::Hex => from_hex(text),
            Encoding::Base64 => from_base64(text),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
        }
    }
}

/// HMAC-SHA256 of `message` under `secret`. HMAC is defined for a key of
/// any length (RFC 2104 hashes over-long keys and zero-pads short ones),
/// so `new_from_slice` cannot actually fail here.
pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
    to_hex(&hmac_sha256(secret, message))
}

/// Compares two byte strings without an early-exit on the first differing
/// byte. This is the whole reason this crate exists rather than a
/// two-line `expected == provided`: a `==` on `&[u8]`/`String` returns as
/// soon as it finds a mismatch, so the time it takes leaks *how many
/// leading bytes* of the guess were right, which is enough to forge a
/// signature one byte at a time against a remote endpoint.
///
/// `subtle`'s `ct_eq` does the comparison with no data-dependent
/// branches. The length check in front of it is not constant-time, and
/// deliberately so: the length of a SHA256 digest is public (always 32
/// bytes), so leaking "your signature was the wrong length" leaks
/// nothing an attacker didn't already know.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Decodes hex, case-insensitively (some senders uppercase it). Returns
/// `None` for anything that isn't a whole number of hex byte pairs —
/// callers turn that into a "malformed header" verdict rather than a
/// signature mismatch, so a typo'd header doesn't look like an attack.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            Some(hi << 4 | lo)
        })
        .collect()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(B64_ALPHABET[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(n >> 6 & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Standard-alphabet base64 decode. Padding is optional (some senders
/// strip it); trailing garbage or a stray non-alphabet byte is `None`,
/// i.e. "malformed", not "mismatch".
pub fn from_base64(text: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<u8>>();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut padding = 0usize;
    for &c in &bytes {
        if c == b'=' {
            padding += 1;
            if padding > 2 {
                return None;
            }
            continue;
        }
        if padding > 0 {
            // A data byte after padding started: not valid base64.
            return None;
        }
        let v = b64_val(c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    // Leftover bits of a truncated group must be zero in canonical base64.
    if nbits > 0 && (acc & ((1 << nbits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1 — an HMAC-SHA256 vector published by the IETF,
    /// so this pins our HMAC to something checkable outside this repo (and
    /// reproducible with:
    /// `printf 'Hi There' | openssl dgst -sha256 -mac HMAC -macopt hexkey:0b0b...0b`).
    #[test]
    fn hmac_matches_rfc_4231_test_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hex_round_trips_and_is_case_insensitive() {
        let digest = hmac_sha256(b"k", b"m");
        let hex = to_hex(&digest);
        assert_eq!(from_hex(&hex).unwrap(), digest.to_vec());
        assert_eq!(
            from_hex(&hex.to_uppercase()).unwrap(),
            from_hex(&hex).unwrap()
        );
    }

    #[test]
    fn malformed_hex_is_none_not_a_panic() {
        assert!(from_hex("abc").is_none(), "odd length");
        assert!(from_hex("zz").is_none(), "non-hex characters");
        assert!(from_hex("").is_none(), "empty");
        assert!(from_hex("ab\u{00e9}c").is_none(), "multi-byte char");
    }

    /// Cross-checked against
    /// `printf '{"order_id":1234}' | openssl dgst -sha256 -hmac 'shpss_generic_secret' -binary | base64`
    #[test]
    fn base64_matches_openssl_for_a_real_digest() {
        assert_eq!(
            to_base64(&hmac_sha256(
                b"shpss_generic_secret",
                br#"{"order_id":1234}"#
            )),
            "qhABbY7I/iJKAkxKUsJ+LtrEqiKlAtgaIJFyvb8Uh/s="
        );
    }

    #[test]
    fn base64_round_trips_including_both_padding_lengths() {
        for input in [&b"a"[..], b"ab", b"abc", b"abcd", &[0u8; 32][..]] {
            let encoded = to_base64(input);
            assert_eq!(from_base64(&encoded).unwrap(), input.to_vec(), "{encoded}");
        }
        // Padding is optional on the way back in.
        assert_eq!(from_base64("YWJjZA").unwrap(), b"abcd".to_vec());
    }

    #[test]
    fn malformed_base64_is_none_not_a_panic() {
        assert!(from_base64("!!!!").is_none(), "non-alphabet");
        assert!(from_base64("YQ===").is_none(), "over-padded");
        assert!(from_base64("YQ==Y").is_none(), "data after padding");
        assert!(from_base64("").is_none(), "empty");
    }

    #[test]
    fn constant_time_eq_agrees_with_plain_equality() {
        let a = hmac_sha256(b"secret", b"body");
        let b = hmac_sha256(b"secret", b"body");
        let c = hmac_sha256(b"secret", b"bodyy");
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        // Differing only in the last byte must still be rejected — the
        // case a truncated/prefix comparison would wave through.
        let mut almost = a;
        almost[31] ^= 0x01;
        assert!(!constant_time_eq(&a, &almost));
        // And differing only in the first byte, the case a timing attack
        // walks byte-by-byte from.
        let mut almost = a;
        almost[0] ^= 0x01;
        assert!(!constant_time_eq(&a, &almost));
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
